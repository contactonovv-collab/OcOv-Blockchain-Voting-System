import os
import smtplib
import ssl
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")


def send_otp_email(receiver_email, otp):

    if not MAIL_USERNAME or not MAIL_PASSWORD:
        raise ValueError("Email credentials are not configured.")

    message = EmailMessage()
    message["Subject"] = "OcOv - Email Verification"
    message["From"] = MAIL_USERNAME
    message["To"] = receiver_email

    message.set_content(f"""
Hello,

Your email verification code for OcOv (One College One Vote) is:

{otp}

This code expires in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
OcOv Team
    """)

    context = ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(message)

    return True