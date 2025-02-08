import os
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
    return get_secret_value("AMAZON_DOWNLOAD_PASSWORD")

# Load the login password secret on startup.
DOWNLOAD_PASSWORD = get_download_password()

def generate_presigned_url_for_object(bucket: str, key: str, expiration: int):
    """
    Generate a presigned URL for an S3 object using the credentials for the s3_reader IAM user.
    The credentials are retrieved as separate secrets from AWS Secrets Manager:
      - S3_READER_ACCESS_KEY
      - S3_READER_SECRET_KEY

    :param bucket: Name of the S3 bucket.
    :param key: S3 object key.
    :param expiration: Expiration time in seconds.
    :return: Tuple of (presigned URL, expiration datetime)
    """
    access_key = get_secret_value("S3_READER_ACCESS_KEY")
    secret_key = get_secret_value("S3_READER_SECRET_KEY")
    
    if not access_key or not secret_key:
        raise ValueError("Missing s3 reader access key or secret key from Secrets Manager.")

    # Create a boto3 session using the s3_reader user's credentials.
    session_with_user = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    s3_client = session_with_user.client("s3")
    presigned_url = s3_client.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiration
    )
    expiration_datetime = datetime.now(timezone.utc) + timedelta(seconds=expiration)
    return presigned_url, expiration_datetime

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
    
    # Define the S3 object.
    bucket = "6190-amazon-data"
    key = "2023/products/meta_Amazon_Fashion.jsonl.gz"
    expiration_seconds = 604800  # 7 days in seconds

    try:
        presigned_url, expiration_dt = generate_presigned_url_for_object(bucket, key, expiration_seconds)
    except Exception as e:
        flash(f"Error generating presigned URL: {e}")
        presigned_url = None
        expiration_dt = None

    return render_template("hello.html", presigned_url=presigned_url, expiration_datetime=expiration_dt)

if __name__ == "__main__":
    # Run on 0.0.0.0:8080 for App Runner compatibility.
    app.run(debug=True, host="0.0.0.0", port=8080)
