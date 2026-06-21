import os
import logging
import smtplib
from email.mime.text import MIMEText

log = logging.getLogger(__name__)


def send_email(subject, body):
    sender = os.environ.get("WATCHDOG_EMAIL")
    password = os.environ.get("WATCHDOG_PASSWORD")
    if not sender or not password:
        log.error("send_email: WATCHDOG_EMAIL or WATCHDOG_PASSWORD not set; skipping %r", subject)
        return False
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = sender
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30) as smtp:
                smtp.login(sender, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                smtp.starttls()
                smtp.login(sender, password)
                smtp.send_message(msg)
        return True
    except Exception as exc:
        log.error("send_email failed (%s): %s", subject, exc)
        return False
