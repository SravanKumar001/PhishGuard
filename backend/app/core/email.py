from email.message import EmailMessage
from smtplib import SMTP

from app.core.config import get_settings


def smtp_is_configured() -> bool:
    settings = get_settings()
    return bool(settings.smtp_host)


def send_account_email(recipient: str, subject: str, body: str) -> None:
    settings = get_settings()
    if not smtp_is_configured():
        raise RuntimeError("SMTP is not configured.")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    with SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password or "")
        smtp.send_message(message)
