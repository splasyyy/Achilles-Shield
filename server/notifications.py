import os
import json
import requests
import smtplib
from email.message import EmailMessage


def send_slack_alert(alert: dict) -> None:
    """Send a concise Slack alert via webhook. alert should include host_id, action, targets, reason, confidence, threat_type."""
    webhook = os.environ.get("SLACK_WEBHOOK")
    if not webhook:
        # No webhook configured — skip silently
        return

    text = (
        f"🚨 [{alert.get('threat_type', 'threat').upper()}] on {alert.get('host_id')}\n"
        f"Action: {alert.get('action')} | Targets: {alert.get('targets')}\n"
        f"Confidence: {alert.get('confidence')} | Reason: {alert.get('reason')}"
    )

    payload = {"text": text}
    try:
        requests.post(webhook, json=payload, timeout=5)
    except Exception as e:
        print(f"Error sending Slack alert: {e}")


def send_email_alert(alert: dict) -> None:
    """Send an email alert if SMTP is configured. Minimal, opt-in by env vars."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    from_addr = os.environ.get("ALERT_FROM", smtp_user)
    to_addr = os.environ.get("ALERT_TO")

    if not (smtp_host and smtp_user and smtp_pass and to_addr):
        return

    subject = f"[Achilles Shield] {alert.get('threat_type', 'Threat')} on {alert.get('host_id')}"
    body = (
        f"Host: {alert.get('host_id')}\n"
        f"Threat: {alert.get('threat_type')}\n"
        f"Action: {alert.get('action')}\n"
        f"Targets: {alert.get('targets')}\n"
        f"Confidence: {alert.get('confidence')}\n"
        f"Reason: {alert.get('reason')}\n"
    )

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
    except Exception as e:
        print(f"Error sending email alert: {e}")
