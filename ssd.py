import subprocess
import smtplib
from email.message import EmailMessage
import socket

# Config
AD_USERNAME = "testuser@domain.com"   # Replace with a real AD user
AD_PASSWORD = "SuperSecretPassword"   # Replace securely
EMAIL_FROM = 'monitor@example.com'
EMAIL_TO = 'admin@example.com'
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 25

def send_alert(hostname, message):
    msg = EmailMessage()
    msg.set_content(message)
    msg['Subject'] = f'SSSD AUTH ALERT on {hostname}'
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.send_message(msg)
    except Exception as e:
        with open("/var/log/sssd_auth_monitor.log", "a") as f:
            f.write(f"Failed to send alert email: {e}\n")

def test_ssh_login(username, password):
    hostname = "localhost"
    try:
        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            f"{username}@{hostname}", "echo success"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        stdout = result.stdout.decode()
        stderr = result.stderr.decode()

        if "Permission denied" in stderr or result.returncode != 0:
            return False
        return True

    except Exception as e:
        return False

def main():
    hostname = socket.gethostname()
    if not test_ssh_login(AD_USERNAME, AD_PASSWORD):
        send_alert(hostname, f"[{hostname}] SSSD authentication test FAILED for user {AD_USERNAME}.")

if __name__ == "__main__":
    main()
