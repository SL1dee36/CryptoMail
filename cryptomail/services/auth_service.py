# Description: User registration, Streebog password hashing, 3-Factor Authentication (OTP/TOTP), and password reset.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import hashlib
import hmac
import os
import random
import re
import secrets
import string
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from crypto.streebog import pbkdf2_streebog512
from crypto.ecp import generate_ecp_keypair, export_ecp_private_key_pem, export_ecp_public_key_pem, issue_self_signed_certificate
from crypto.rsa import generate_rsa_keypair, export_private_key_pem, export_public_key_pem
from cryptomail.models.user import User
from cryptomail.services.mail_server import send_system_email

# Strict validation regexes
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#^])[A-Za-z\d@$!%*?&_\-#^]{8,64}$")

# In-memory storage for pending 3FA factor 2 (email OTP) sessions
# Format: {session_id: {"user_id": user_id, "otp": "123456", "expires_at": timestamp}}
PENDING_3FA_SESSIONS: Dict[str, Dict] = {}
PENDING_RESET_SESSIONS: Dict[str, Dict] = {}


def validate_registration_inputs(username: str, email: str, password: str) -> Tuple[bool, Optional[str]]:
    if not USERNAME_REGEX.match(username):
        return False, "Логин должен содержать от 3 до 20 символов (латинские буквы, цифры, дефис, подчеркивание)."
    if not EMAIL_REGEX.match(email):
        return False, "Некорректный адрес электронной почты."
    if not PASSWORD_REGEX.match(password):
        return False, (
            "Пароль должен содержать минимум 8 символов, включая заглавную и строчную буквы, "
            "цифру и хотя бы один спецсимвол (@, $, !, %, *, ?, &, _, -, #, ^)."
        )
    return True, None


def hash_password_streebog(password: str, salt: bytes = None) -> Tuple[str, str]:
    """Hashes password with GOST R 34.11-2012 Streebog-512 and salt via PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    dk = pbkdf2_streebog512(password, salt, iterations=1000, dklen=64)
    return dk.hex(), salt.hex()


def verify_password_streebog(password: str, password_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    computed, _ = hash_password_streebog(password, salt)
    return hmac.compare_digest(computed, password_hash_hex)


hash_password = hash_password_streebog
verify_password = verify_password_streebog



# RFC 6238 TOTP implementation
def generate_totp_secret() -> str:
    """Generates base32 secret for TOTP."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def get_totp_token(secret_b32: str, time_step: int = 30) -> str:
    """Computes current 6-digit TOTP token."""
    pad_len = (8 - (len(secret_b32) % 8)) % 8
    padded_secret = secret_b32 + "=" * pad_len
    key = base64.b32decode(padded_secret, casefold=True)
    t = int(time.time() // time_step)
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def generate_totp_code(secret_b32: str, timestamp: Optional[int] = None, time_step: int = 30) -> str:
    if timestamp is not None:
        pad_len = (8 - (len(secret_b32) % 8)) % 8
        padded_secret = secret_b32 + "=" * pad_len
        key = base64.b32decode(padded_secret, casefold=True)
        t = int(timestamp // time_step)
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"
    return get_totp_token(secret_b32, time_step=time_step)



def verify_totp_token(secret_b32: str, token: str, time_step: int = 30, window: int = 1) -> bool:
    """Verifies TOTP token with +/- window tolerance."""
    if not secret_b32 or not token or not token.isdigit():
        return False
    pad_len = (8 - (len(secret_b32) % 8)) % 8
    padded_secret = secret_b32 + "=" * pad_len
    try:
        key = base64.b32decode(padded_secret, casefold=True)
    except Exception:
        return False

    current_t = int(time.time() // time_step)
    for delta in range(-window, window + 1):
        t = current_t + delta
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        if f"{code:06d}" == token.strip():
            return True
    return False


def generate_recovery_codes(count: int = 8) -> List[str]:
    """Generates 8-character single-use emergency recovery codes using CSPRNG."""
    chars = string.ascii_uppercase + string.digits
    codes = []
    for _ in range(count):
        part1 = "".join(secrets.choice(chars) for _ in range(4))
        part2 = "".join(secrets.choice(chars) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes


from crypto.rsa32k import (
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_or_create_rsa_keypair,
)


def register_user(
    db: Session,
    username: str,
    email: str,
    password: str,
    role: str = "user",
    rsa_key_size: int = 4096,
) -> Tuple[Optional[User], Optional[str]]:
    valid, err = validate_registration_inputs(username, email, password)
    if not valid:
        return None, err

    # Check existence
    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        return None, "Пользователь с таким именем или email уже существует."

    pwd_hash, salt_hex = hash_password_streebog(password)
    totp_sec = generate_totp_secret()
    rec_codes = generate_recovery_codes()

    # Pre-generate user's ECP and RSA keys (default 4096 bits or user-chosen)
    ecp_priv, ecp_pub = generate_ecp_keypair()
    rsa_priv, rsa_pub = get_or_create_rsa_keypair(key_size=rsa_key_size)

    user = User(
        username=username,
        email=email,
        password_hash=pwd_hash,
        salt=salt_hex,
        role=role,
        totp_secret=totp_sec,
        ecp_public_key=export_ecp_public_key_pem(ecp_pub),
        rsa_public_key=export_public_key_pem(rsa_pub),
    )
    user.recovery_codes_list = rec_codes
    user.ecp_private_key = export_ecp_private_key_pem(ecp_priv)
    user.rsa_private_key = export_private_key_pem(rsa_priv)

    db.add(user)
    db.commit()
    db.refresh(user)

    # Issue initial self-signed digital certificate
    cert = issue_self_signed_certificate(user.username, user.id, ecp_priv, ecp_pub)
    import json
    user.ecp_certificate = json.dumps(cert)
    db.commit()

    return user, None


def start_3fa_login(db: Session, login_input: str, password: str) -> Tuple[Optional[str], Optional[User], Optional[str]]:
    """
    Factor 1: Login & Password check.
    If valid, generates Factor 2 email OTP and dispatches email to local SMTP server.
    Returns (session_id, user, error_message).
    """
    user = db.query(User).filter(
        (User.username == login_input) | (User.email == login_input)
    ).first()
    if not user:
        return None, None, "Неверный логин или пароль."

    if not verify_password_streebog(password, user.password_hash, user.salt):
        return None, None, "Неверный логин или пароль."

    # Generate 6-digit email OTP using CSPRNG
    otp_code = f"{secrets.randbelow(900000) + 100000:06d}"
    session_id = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")

    PENDING_3FA_SESSIONS[session_id] = {
        "user_id": user.id,
        "otp": otp_code,
        "attempts": 0,
        "factor2_passed": False,
        "expires_at": time.time() + 300,  # 5 minutes
    }

    # Dispatch email through local SMTP server
    subject = f"Код подтверждения: {otp_code}"
    body = (
        f"Здравствуйте, {user.username}!\n\n"
        f"Ваш одноразовый код для входа: {otp_code}\n\n"
        f"Код действителен в течение 5 минут. Если вы не выполняли вход, проигнорируйте это письмо.\n"
        f"--\nСлужба безопасности CryptoMail Local SMTP"
    )
    send_system_email(user.email, subject, body)

    return session_id, user, None


def verify_3fa_factor2(session_id: str, otp_code: str) -> Tuple[bool, Optional[str]]:
    """Verifies Factor 2: Email OTP with attempt rate-limiting."""
    sess = PENDING_3FA_SESSIONS.get(session_id)
    if not sess:
        return False, "Сессия авторизации истекла или не найдена. Начните вход заново."

    if time.time() > sess["expires_at"]:
        PENDING_3FA_SESSIONS.pop(session_id, None)
        return False, "Срок действия кода подтверждения истек."

    sess["attempts"] = sess.get("attempts", 0) + 1
    if sess["attempts"] > 5:
        PENDING_3FA_SESSIONS.pop(session_id, None)
        return False, "Превышено максимальное количество попыток (5). Начните вход заново."

    if sess["otp"] != otp_code.strip():
        return False, f"Неверный одноразовый код из письма. Осталось попыток: {max(0, 5 - sess['attempts'])}."

    sess["factor2_passed"] = True
    return True, None


def verify_3fa_factor3(arg1: Any, arg2: Any, arg3: Any) -> Tuple[Optional[User], Optional[str]]:
    """
    Verifies Factor 3: TOTP code OR single-use emergency recovery code.
    Accepts either (db, session_id, code_input) or (session_id, code_input, db).
    """
    if isinstance(arg1, Session) or hasattr(arg1, "query"):
        db = arg1
        session_id = arg2
        code_input = arg3
    elif isinstance(arg3, Session) or hasattr(arg3, "query"):
        session_id = arg1
        code_input = arg2
        db = arg3
    else:
        session_id = arg1
        code_input = arg2
        db = arg3

    sess = PENDING_3FA_SESSIONS.get(session_id)
    if not sess or not sess.get("factor2_passed"):
        return None, "Предыдущие факторы авторизации не пройдены."

    user = db.query(User).filter(User.id == sess["user_id"]).first()
    if not user:
        return None, "Пользователь не найден."

    clean_code = code_input.strip()

    # Check TOTP token
    if verify_totp_token(user.totp_secret, clean_code):
        PENDING_3FA_SESSIONS.pop(session_id, None)
        return user, None

    # Check Single-Use Recovery Codes
    rec_codes = user.recovery_codes_list
    if clean_code in rec_codes:
        # Consume used code
        rec_codes.remove(clean_code)
        user.recovery_codes_list = rec_codes
        db.commit()
        PENDING_3FA_SESSIONS.pop(session_id, None)
        return user, None

    return None, "Неверный одноразовый код доступа (TOTP) или резервный код."


def initiate_password_reset(db: Session, email_or_username: str) -> Tuple[Optional[str], Optional[str]]:
    """Generates a secure email OTP for password reset."""
    ident = email_or_username.strip()
    user = db.query(User).filter(
        (User.email == ident) | (User.username == ident)
    ).first()
    if not user:
        return None, "Если такой пользователь зарегистрирован, код для сброса отправлен на его почту."

    otp = f"{secrets.randbelow(900000) + 100000:06d}"
    reset_session = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
    PENDING_RESET_SESSIONS[reset_session] = {
        "user_id": user.id,
        "otp": otp,
        "attempts": 0,
        "expires_at": time.time() + 600,
    }

    subject = f"Восстановление пароля: код {otp}"
    body = (
        f"Здравствуйте, {user.username}!\n\n"
        f"Для сброса пароля используйте код: {otp}\n"
        f"Код действителен в течение 10 минут.\n"
        f"Также вы можете воспользоваться одним из ранее сохраненных резервных кодов восстановления.\n"
        f"--\nСлужба безопасности CryptoMail"
    )
    send_system_email(user.email, subject, body)

    return reset_session, None


def complete_password_reset(
    db: Session,
    reset_session: Optional[str],
    email_or_username: str,
    verification_code: str,
    new_password: str,
) -> Tuple[bool, Optional[str]]:
    """Resets password using either an email OTP or a single-use recovery code."""
    valid_pwd, err_pwd = validate_registration_inputs("dummy", "dummy@mail.com", new_password)
    if not valid_pwd:
        return False, err_pwd

    ident = email_or_username.strip()
    user = db.query(User).filter(
        (User.email == ident) | (User.username == ident)
    ).first()
    if not user:
        return False, "Пользователь не найден."

    clean_code = verification_code.strip()
    code_valid = False

    # 1. Check single-use emergency recovery codes
    rec_codes = user.recovery_codes_list
    if clean_code in rec_codes:
        rec_codes.remove(clean_code)
        user.recovery_codes_list = rec_codes
        code_valid = True

    # 2. Check reset session OTP (explicit session_id or active pending OTP for user)
    if not code_valid:
        matched_sid = None
        if reset_session and reset_session in PENDING_RESET_SESSIONS:
            matched_sid = reset_session
        else:
            now = time.time()
            for sid, sdata in list(PENDING_RESET_SESSIONS.items()):
                if sdata.get("user_id") == user.id and now <= sdata.get("expires_at", 0):
                    matched_sid = sid
                    break

        if matched_sid:
            sess = PENDING_RESET_SESSIONS[matched_sid]
            sess["attempts"] = sess.get("attempts", 0) + 1
            if sess["attempts"] > 5:
                PENDING_RESET_SESSIONS.pop(matched_sid, None)
                return False, "Превышено максимальное число попыток ввода кода (5). Запросите код заново."

            if sess.get("otp") == clean_code and time.time() <= sess.get("expires_at", 0):
                PENDING_RESET_SESSIONS.pop(matched_sid, None)
                code_valid = True

    if not code_valid:
        return False, "Неверный или просроченный код подтверждения / код восстановления."

    # Update password with Streebog-512
    pwd_hash, salt_hex = hash_password_streebog(new_password)
    user.password_hash = pwd_hash
    user.salt = salt_hex
    db.commit()

    return True, None


def seed_default_users(db: Optional[Session] = None):
    """Initializes default pre-seeded users for immediate testing."""
    close_when_done = False
    if db is None:
        from cryptomail.database import SessionLocal
        db = SessionLocal()
        close_when_done = True
    try:
        users_to_create = [
            ("admin", "admin@cryptomail.local", "AdminPassword123!", "admin"),
            ("alice", "alice@cryptomail.local", "AlicePassword123!", "user"),
            ("bob", "bob@cryptomail.local", "BobPassword123!", "user"),
            ("guest", "guest@cryptomail.local", "GuestPassword123!", "guest"),
        ]
        for uname, uemail, upwd, urole in users_to_create:
            existing = db.query(User).filter(User.username == uname).first()
            if not existing:
                register_user(db, uname, uemail, upwd, role=urole)
            elif not existing.recovery_codes_list:
                existing.recovery_codes_list = generate_recovery_codes()
                db.commit()
    finally:
        if close_when_done:
            db.close()


def request_password_reset(db: Session, email_or_username: str) -> Tuple[bool, Optional[str]]:
    sess, err = initiate_password_reset(db, email_or_username)
    return sess is not None, sess or err


def reset_password_with_email_code(db: Session, session_id: str, code: str, new_password: str, email: str = "") -> Tuple[bool, Optional[str]]:
    return complete_password_reset(db, session_id, email, code, new_password)


def reset_password_with_recovery_code(db: Session, username: str, recovery_code: str, new_password: str) -> Tuple[bool, Optional[str]]:
    return complete_password_reset(db, None, username, recovery_code, new_password)

