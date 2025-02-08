import os
import json
import boto3
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, session, redirect, url_for, flash

app = Flask(__name__)
# Use an environment variable for the Flask secret key (with a default for local testing)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-key")

def get_secret_value(secret_name: str) -> str:
    """
    Retrieve a secret value from AWS Secrets Manager.
    
    :param secret_name: The name of the secret in Secrets Manager.
    :return: The secret string if available, otherwise None.
    """
    try:
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        app.logger.error(f"Error retrieving secret '{secret_name}': {e}")
        return None

    if "SecretString" in response:
        return response["SecretString"]
    else:
        return response["SecretBinary"].decode("utf-8")

def get_download_password() -> str:
    """
    Retrieve the login password from AWS Secrets Manager.
    The secret name is AMAZON_DOWNLOAD_PASSWORD.
    """
    return json.loads(get_secret_value("AMAZON_DOWNLOAD_PASSWORD")).get("AMAZON_DOWNLOAD_PASSWORD")

# Load the login password secret on startup.
DOWNLOAD_PASSWORD = get_download_password()

def get_s3_reader_credentials():
    """
    Retrieve the s3_reader credentials from AWS Secrets Manager.
    The secret name is S3_READER_CREDENTIALS and is expected to be a JSON string
    containing the keys "S3_READER_ACCESS_KEY" and "S3_READER_SECRET_KEY".
    
    :return: A dictionary with the credentials, or None if retrieval fails.
    """
    secret_name = "S3_READER_CREDENTIALS"
    secret_string = get_secret_value(secret_name)
    if not secret_string:
        app.logger.error(f"Could not retrieve secret string for '{secret_name}'.")
        return None
    try:
        credentials = json.loads(secret_string)
    except Exception as e:
        app.logger.error(f"Error parsing JSON for secret '{secret_name}': {e}")
        return None
    return credentials

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Retrieve form inputs.
        password_input = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "")

        # Validate captcha.
        try:
            expected_captcha = int(session.get("captcha_answer", ""))
            if int(captcha_input) != expected_captcha:
                flash("Incorrect captcha answer. Please try again.")
                return redirect(url_for("login"))
        except ValueError:
            flash("Invalid captcha input. Please enter a number.")
            return redirect(url_for("login"))

        # Validate password against the secret from Secrets Manager.
        if DOWNLOAD_PASSWORD is None:
            flash("Password validation not available (secret not retrieved).")
            return redirect(url_for("login"))

        if password_input == DOWNLOAD_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("hello"))
        else:
            flash("Incorrect password. Please try again.")
            return redirect(url_for("login"))
    else:
        # For GET requests, generate a new simple math captcha.
        import random
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        session["captcha_answer"] = num1 + num2
        captcha_question = f"What is {num1} + {num2}?"
        return render_template("index.html", captcha_question=captcha_question)

@app.route("/hello")
def hello():
    # Only allow access if the user is authenticated.
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    
    # Define the S3 bucket, prefix and expiration (7 days)
    bucket = "6190-amazon-data"
    prefix = "2023/"
    expiration_seconds = 604800  # 7 days in seconds

    # Retrieve the s3_reader credentials and create a session
    credentials = get_s3_reader_credentials()
    if not credentials:
        flash("Error retrieving s3_reader credentials.")
        return render_template("hello.html", folder_structure=None, soonest_expiration=None)
    access_key = credentials.get("S3_READER_ACCESS_KEY")
    secret_key = credentials.get("S3_READER_SECRET_KEY")
    if not access_key or not secret_key:
        flash("Missing s3_reader credentials in secret.")
        return render_template("hello.html", folder_structure=None, soonest_expiration=None)
    session_with_user = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    s3_client = session_with_user.client("s3")

    # List all objects recursively under the given prefix.
    objects = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        if "Contents" in page:
            for obj in page["Contents"]:
                key = obj["Key"]
                # Optionally skip “folder” keys (which end with a '/')
                if key.endswith("/"):
                    continue
                objects.append(key)

    # For each object, generate a presigned URL and record its expiration time.
    signed_objects = []
    expiration_dates = []
    for key in objects:
        url = s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expiration_seconds
        )
        # Each presigned URL's expiration is computed as current time plus expiration_seconds.
        # (Because the generation calls occur sequentially, these may differ slightly.)
        expiration_dt = datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds)
        signed_objects.append({"key": key, "url": url})
        expiration_dates.append(expiration_dt)

    # Compute the soonest (i.e. earliest) expiration date among all objects.
    soonest_expiration = min(expiration_dates) if expiration_dates else None

    # Build a nested folder structure from the keys.
    folder_structure = {}
    for obj in signed_objects:
        # Remove the prefix (if you want to display a cleaner structure)
        relative_key = obj["key"][len(prefix):] if obj["key"].startswith(prefix) else obj["key"]
        parts = relative_key.split("/")
        current = folder_structure
        for i, part in enumerate(parts):
            if part == "":
                continue
            if i == len(parts) - 1:
                # This is a file.
                if "files" not in current:
                    current["files"] = []
                current["files"].append({"name": part, "url": obj["url"]})
            else:
                # This is a folder.
                if "folders" not in current:
                    current["folders"] = {}
                if part not in current["folders"]:
                    current["folders"][part] = {}
                current = current["folders"][part]

    return render_template("hello.html", folder_structure=folder_structure, soonest_expiration=soonest_expiration)

if __name__ == "__main__":
    # Run on 0.0.0.0:8080 for App Runner compatibility.
    app.run(debug=True, host="0.0.0.0", port=8080)
