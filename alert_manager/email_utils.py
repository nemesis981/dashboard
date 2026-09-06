import os
import logging
import smtplib
from email.mime.text import MIMEText

log = logging.getLogger(__name__)


def send_email(subject, body, to=None, cc=None):
    """Send a plain-text email via SMTP.

    to  — recipient address; defaults to WATCHDOG_EMAIL (self-addressed)
    cc  — optional CC address
    SMTP_HOST / SMTP_PORT are read from environment; port 465 uses implicit
    SSL (SMTP_SSL), any other port uses STARTTLS.
    """
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
    msg["To"] = to if to is not None else sender
    if cc is not None:
        msg["Cc"] = cc
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
        # FINDING 6 (route-security-audit-learning-custom-2026-09-05.md): only the
        # failure path logged, so "sent" and "never attempted" were indistinguishable
        # from the journal -- a caller could only prove a failure, never a success.
        log.info("send_email sent (%s) to %s", subject, msg["To"])
        return True
    except Exception as exc:
        log.error("send_email failed (%s): %s", subject, exc)
        return False
