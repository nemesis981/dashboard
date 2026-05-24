#!/usr/bin/env python3
"""Watchdog service that monitors critical services and restarts/alerts on failure."""

import logging
import os
import smtplib
import subprocess
import time
from email.mime.text import MIMEText

SERVICES = [
    "pihole-FTL",
    "clamav-daemon",
    "suricata",
    "dashboard",
    "device-scanner",
]

CHECK_INTERVAL_SECONDS = 120
LOG_PATH = "/home/paul/alert_manager/watchdog.log"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def is_service_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
    )
    return result.returncode == 0


def restart_service(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "restart", service],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logging.error(
            "systemctl restart %s failed: %s",
            service,
            result.stderr.strip(),
        )
        return False
    time.sleep(3)
    return is_service_active(service)


def send_email_alert(service: str) -> None:
    sender = os.environ.get("WATCHDOG_EMAIL")
    password = os.environ.get("WATCHDOG_PASSWORD")

    if not sender or not password:
        logging.error(
            "Cannot send alert for %s: WATCHDOG_EMAIL or WATCHDOG_PASSWORD is not set",
            service,
        )
        return

    subject = f"[Watchdog] Service '{service}' is down and could not be restarted"
    body = (
        f"The watchdog attempted to automatically restart the '{service}' service "
        f"but it remains inactive.\n\n"
        f"Host: {os.uname().nodename}\n"
        f"Please investigate as soon as possible."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = sender

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(sender, password)
            smtp.send_message(msg)
        logging.info("Sent alert email for %s", service)
    except Exception as exc:
        logging.error("Failed to send alert email for %s: %s", service, exc)


def check_service(service: str) -> None:
    if is_service_active(service):
        return

    logging.warning("Service '%s' is down. Attempting automatic restart.", service)
    if restart_service(service):
        logging.info("Service '%s' restarted successfully.", service)
    else:
        logging.error(
            "Service '%s' restart failed. Sending email alert.", service
        )
        send_email_alert(service)


def main() -> None:
    logging.info("Watchdog started. Monitoring: %s", ", ".join(SERVICES))
    while True:
        for service in SERVICES:
            try:
                check_service(service)
            except Exception as exc:
                logging.exception("Unexpected error while checking %s: %s", service, exc)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
