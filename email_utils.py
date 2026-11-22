import os
import json
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
BREVO_API_KEY = os.getenv("BREVO_API_KEY")


def send_otp_email(receiver_email, otp):

    if not MAIL_USERNAME or not BREVO_API_KEY:
        raise ValueError("Email credentials are not configured.")

    payload = {
        "sender": {
            "name": "OcOv Team",
            "email": MAIL_USERNAME
        },
        "to": [
            {
                "email": receiver_email
            }
        ],
        "subject": "OcOv - Email Verification",
        "textContent": f"""
Hello,

Your email verification code for OcOv (One College One Vote) is:

{otp}

This code expires in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
OcOv Team
"""
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=data,
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status in (200, 201, 202)

    except urllib.error.HTTPError as error:
        error_details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Brevo email error: {error_details}") from error
