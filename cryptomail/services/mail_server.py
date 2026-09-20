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

        otp_match = re.search(r"\b(\d{6})\b", body)
        otp_code = otp_match.group(1) if otp_match else None

        clean_rcpt = [r.strip().strip("<>").strip() for r in rcpt_to if r.strip()]
        clean_sender = (mail_from or "system@cryptomail.local").strip().strip("<>").strip()
        body_norm = body.strip()

        for ex in RECEIVED_EMAILS:
            ex_rcpt = [r.strip().strip("<>").strip().lower() for r in ex.get("recipients", [])]
            clean_rcpt_lower = [r.lower() for r in clean_rcpt]
            if any(r in ex_rcpt for r in clean_rcpt_lower) and ex.get("subject") == subject:
                if (otp_code and ex.get("otp_code") == otp_code) or ex.get("body", "").strip() == body_norm:
                    logger.debug(f"[SMTP] Duplicate message detected for {clean_rcpt}: {subject}")
                    return

        item = {
            "id": len(RECEIVED_EMAILS) + 1,
            "sender": clean_sender,
            "recipients": clean_rcpt,
            "to": clean_rcpt[0] if clean_rcpt else "",
            "recipient": clean_rcpt[0] if clean_rcpt else "",
            "subject": subject,
            "body": body_norm,
            "otp_code": otp_code,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "raw": raw_email,
        }
        RECEIVED_EMAILS.insert(0, item)
        if len(RECEIVED_EMAILS) > MAX_STORED_EMAILS:
            RECEIVED_EMAILS.pop()
        logger.info(f"[SMTP] Received email for {clean_rcpt}: {subject}, OTP: {otp_code}")

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


smtp_server = LocalSMTPServer()


def send_system_email(to_email: str, subject: str, body: str, host: str = "127.0.0.1", port: int = 1025) -> bool:
    msg = EmailMessage()
    msg["From"] = "security@cryptomail.local"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    clean_email = to_email.strip().strip("<>").strip()
    body_norm = body.strip()
    otp_match = re.search(r"\b(\d{6})\b", body)
    otp_code = otp_match.group(1) if otp_match else None

    already_in_store = False
    for ex in RECEIVED_EMAILS:
        ex_rcpt = [r.strip().strip("<>").strip().lower() for r in ex.get("recipients", [])]
        if clean_email.lower() in ex_rcpt and ex.get("subject") == subject:
            if (otp_code and ex.get("otp_code") == otp_code) or ex.get("body", "").strip() == body_norm:
                already_in_store = True
                break

    if not already_in_store:
        item = {
            "id": len(RECEIVED_EMAILS) + 1,
            "sender": "security@cryptomail.local",
            "recipients": [clean_email],
            "to": clean_email,
            "recipient": clean_email,
            "subject": subject,
            "body": body_norm,
            "otp_code": otp_code,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "raw": msg.as_string(),
        }
        RECEIVED_EMAILS.insert(0, item)
        if len(RECEIVED_EMAILS) > MAX_STORED_EMAILS:
            RECEIVED_EMAILS.pop()

    try:
        with smtplib.SMTP(host, port, timeout=0.5) as client:
            client.send_message(msg)
    except Exception as e:
        logger.warning(f"Direct SMTP send failed ({e}), saved locally to mail inbox.")

    return True


def get_latest_email_for(recipient: str) -> Optional[Dict[str, Any]]:
    clean_target = recipient.strip().strip("<>").lower()
    for item in get_all_received_emails():
        clean_rcpts = [r.strip().strip("<>").lower() for r in item.get("recipients", [])]
        if any(clean_target in r for r in clean_rcpts):
            return item
    return None


def get_all_received_emails() -> List[Dict[str, Any]]:
    unique_emails = []
    seen = set()
    for item in RECEIVED_EMAILS:
        rcpts = tuple(sorted(r.strip().strip("<>").lower() for r in item.get("recipients", [])))
        subj = (item.get("subject") or "").strip()
        otp = item.get("otp_code")
        body_norm = (item.get("body") or "").strip()
        key = (rcpts, subj, otp if otp else body_norm)
        if key not in seen:
            seen.add(key)
            unique_emails.append(item)
    return unique_emails


def clear_received_emails():
    RECEIVED_EMAILS.clear()


def start_mail_server():
    pass


def stop_mail_server():
    pass

