import smtplib
from email.message import EmailMessage

from .config import get_settings


settings = get_settings()


def send_email(
    recipient: str,
    subject: str,
    body: str,
) -> None:
    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = (
        f"{settings.email_from_name} "
        f"<{settings.email_from}>"
    )
    message["To"] = recipient

    message.set_content(body)

    with smtplib.SMTP(
        settings.smtp_host,
        settings.smtp_port,
        timeout=20,
    ) as smtp:

        smtp.starttls()

        smtp.login(
            settings.smtp_username,
            settings.smtp_password,
        )

        smtp.send_message(message)


def send_verification_email(
    recipient: str,
    token: str,
) -> None:

    url = (
        f"{settings.public_api_url}"
        f"/api/v1/auth/verify-email"
        f"?token={token}"
    )

    body = f"""
Hello,

Please verify your email address using this link:

{url}

This link expires in
{settings.email_verification_hours} hours.

If you did not create this account,
you can ignore this email.

Regards,
{settings.email_from_name}
""".strip()

    send_email(
        recipient=recipient,
        subject="Verify your email",
        body=body,
    )


def send_password_reset_email(
    recipient: str,
    token: str,
) -> None:

    url = (
        f"{settings.public_api_url}"
        f"/api/v1/auth/reset-password"
        f"?token={token}"
    )

    body = f"""
Hello,

A password reset was requested for your account.

Use this token with the reset-password API:

{token}

The reset endpoint is:

{url}

This token expires in
{settings.password_reset_minutes} minutes.

If you did not request this,
you can ignore this email.

Regards,
{settings.email_from_name}
""".strip()

    send_email(
        recipient=recipient,
        subject="Reset your password",
        body=body,
    )