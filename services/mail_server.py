# Description: Built-in asynchronous SMTP server (RFC 5321) for local 3FA verification email delivery.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import asyncio
import email
from email.message import EmailMessage
from email.policy import default as default_policy
import logging
import re
import smtplib
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mail_server")

# In-memory store of received emails for real-time Web UI viewing
RECEIVED_EMAILS: List[Dict[str, Any]] = []
MAX_STORED_EMAILS = 100


class LocalSMTPProtocol(asyncio.Protocol):
    """Asynchronous RFC 5321 SMTP Protocol Handler."""

    def __init__(self, on_message_received):
        self.transport = None
        self.buffer = ""
        self.in_data = False
        self.data_lines = []
        self.mail_from = ""
        self.rcpt_to = []
        self.on_message_received = on_message_received

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(b"220 127.0.0.1 Embedded SMTP Service Ready for 3FA\r\n")

    def data_received(self, data):
        self.buffer += data.decode("utf-8", errors="replace")
        while "\r\n" in self.buffer:
            line, self.buffer = self.buffer.split("\r\n", 1)
            self.handle_line(line)

    def handle_line(self, line: str):
        if self.in_data:
            if line == ".":
                self.in_data = False
                raw_email = "\r\n".join(self.data_lines)
                self.on_message_received(self.mail_from, self.rcpt_to, raw_email)
                self.data_lines = []
                self.transport.write(b"250 2.0.0 Ok: message queued\r\n")
            else:
                # Dot-un той-stuffing
                if line.startswith(".."):
                    line = line[1:]
                self.data_lines.append(line)
            return

        cmd = line.strip().upper()
        if cmd.startswith("HELO") or cmd.startswith("EHLO"):
            self.transport.write(b"250-127.0.0.1 Hello\r\n250 8BITMIME\r\n")
        elif cmd.startswith("MAIL FROM:"):
            self.mail_from = line[10:].strip().strip("<>")
            self.rcpt_to = []
            self.transport.write(b"250 2.1.0 Ok\r\n")
        elif cmd.startswith("RCPT TO:"):
            recipient = line[8:].strip().strip("<>")
            self.rcpt_to.append(recipient)
            self.transport.write(b"250 2.1.5 Ok\r\n")
        elif cmd == "DATA":
            self.in_data = True
            self.data_lines = []
            self.transport.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
        elif cmd == "RSET":
            self.mail_from = ""
            self.rcpt_to = []
            self.data_lines = []
            self.in_data = False
            self.transport.write(b"250 2.0.0 Ok\r\n")
        elif cmd == "NOOP":
            self.transport.write(b"250 2.0.0 Ok\r\n")
        elif cmd == "QUIT":
            self.transport.write(b"221 2.0.0 Bye\r\n")
            self.transport.close()
        else:
            self.transport.write(b"502 5.5.2 Error: command not recognized\r\n")


class LocalSMTPServer:
    """Manages the background SMTP server lifecycle."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1025):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.is_running = False

    def _on_message_received(self, mail_from: str, rcpt_to: List[str], raw_email: str):
        parsed = email.message_from_string(raw_email, policy=default_policy)
        subject = parsed.get("Subject", "(No Subject)")
        body = ""
        if parsed.is_multipart():
            for part in parsed.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break
            if not body:
                for part in parsed.walk():
                    if part.get_content_type() == "text/html":
                        body = part.get_content()
                        break
        else:
            body = parsed.get_content()

        # Extract 6-digit OTP code if present in body
        otp_match = re.search(r"\b(\d{6})\b", body)
        otp_code = otp_match.group(1) if otp_match else None

        item = {
            "id": len(RECEIVED_EMAILS) + 1,
            "sender": mail_from or "system@cryptomail.local",
            "recipients": rcpt_to,
            "subject": subject,
            "body": body,
            "otp_code": otp_code,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "raw": raw_email,
        }
        RECEIVED_EMAILS.insert(0, item)
        if len(RECEIVED_EMAILS) > MAX_STORED_EMAILS:
            RECEIVED_EMAILS.pop()
        logger.info(f"[SMTP] Received email for {rcpt_to}: {subject}, OTP: {otp_code}")

    async def start(self):
        loop = asyncio.get_running_loop()
        try:
            self.server = await loop.create_server(
                lambda: LocalSMTPProtocol(self._on_message_received),
                self.host,
                self.port,
            )
            self.is_running = True
            logger.info(f"Local SMTP server started on {self.host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind SMTP server to {self.host}:{self.port}: {e}. (Will use in-app delivery)")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
            logger.info("Local SMTP server stopped.")


# Singleton SMTP Server instance
smtp_server = LocalSMTPServer()


def send_system_email(to_email: str, subject: str, body: str, host: str = "127.0.0.1", port: int = 1025) -> bool:
    """
    Sends an email using the local SMTP server.
    Also ensures the local in-memory store has a copy so test callers or same-process handlers can access it.
    """
    msg = EmailMessage()
    msg["From"] = "security@cryptomail.local"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=0.2) as client:
            client.send_message(msg)
    except Exception as e:
        logger.warning(f"Direct SMTP send failed ({e}), recording directly to mail inbox.")

    # Record to in-memory store for local process visibility
    otp_match = re.search(r"\b(\d{6})\b", body)
    otp_code = otp_match.group(1) if otp_match else None
    item = {
        "id": len(RECEIVED_EMAILS) + 1,
        "sender": "security@cryptomail.local",
        "recipients": [to_email],
        "subject": subject,
        "body": body,
        "otp_code": otp_code,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "raw": msg.as_string(),
    }
    if not any(e.get("body") == body and e.get("recipients") == [to_email] for e in RECEIVED_EMAILS):
        RECEIVED_EMAILS.insert(0, item)
    return True


def get_latest_email_for(recipient: str) -> Optional[Dict[str, Any]]:
    for item in RECEIVED_EMAILS:
        if any(recipient.lower() in r.lower() for r in item["recipients"]):
            return item
    return None
