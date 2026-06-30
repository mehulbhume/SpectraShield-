# ~/firewall-agent/email_alert.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ── Config ──────────────────────────────────────────────────
SENDER_EMAIL = "uttekaraaradhya@gmail.com"
SENDER_PASSWORD = "wojturrpujxurbfc"  # App Password (spaces hatao)
RECEIVER_EMAIL = "uttekaraaradhya@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_alert(event_type: str, severity: int, source_ip: str, details: dict):
    """Send email alert for high severity events."""
    
    subject = f"[EDR ALERT] {event_type.upper()} | Severity: {severity}/10"
    
    body = f"""
🚨 EDR Security Alert — AaruPC

Event Type  : {event_type}
Severity    : {severity}/10
Source IP   : {source_ip}
Timestamp   : {datetime.now().isoformat()}
Details     : {details}

MITRE ATT&CK:
  Tactic    : {"Impact" if event_type == "canary_triggered" else "Execution"}
  Technique : {"T1486" if event_type == "canary_triggered" else "T1059"}

— EDR Security Agent
    """.strip()

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        print(f"[EmailAlert] ✅ Alert sent — {event_type} | severity={severity}")

    except Exception as e:
        print(f"[EmailAlert] ❌ Failed: {e}")

# ── Test ─────────────────────────────────────────────────────
if __name__ == "__main__":
    send_alert(
        event_type="canary_triggered",
        severity=10,
        source_ip="192.168.1.50",
        details={"file": "canary_doc.txt"}
    )