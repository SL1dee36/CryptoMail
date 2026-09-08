# Description: Message delivery service handling hybrid encryption, digital signing, decryption, and verification.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import hmac
import json
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session
from crypto.ecp import (
    load_ecp_private_key_pem,
    load_ecp_public_key_pem,
    sign_message,
    verify_certificate,
    verify_message_signature,
)
from crypto.kuznyechik import Kuznyechik
from crypto.rsa import (
    load_private_key_pem,
    load_public_key_pem,
    rsa_decrypt_hybrid,
    rsa_encrypt_hybrid,
)
from crypto.streebog import hmac_streebog512, pbkdf2_streebog512, streebog512
from cryptomail.models.message import Message
from cryptomail.models.user import User

SUPPORTED_ENCRYPTION_TYPES = [
    "RSA",
    "RSA-2048",
    "RSA-4096",
    "RSA-8192",
    "RSA-32K",
    "RSA-32768",
    "KUZNYECHIK",
    "KUZNYECHIK-256",
]


# ---------------------------------------------------------------------------
# Kuznyechik symmetric key derivation helpers
# ---------------------------------------------------------------------------

def _derive_kuznyechik_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derives a 32-byte Kuznyechik key from a user-supplied passphrase via PBKDF2-Streebog-512."""
    return pbkdf2_streebog512(passphrase.encode("utf-8"), salt, iterations=10000, dklen=32)


def _derive_personal_kuznyechik_key(user: User) -> bytes:
    """
    Derives a deterministic 32-byte personal symmetric key for the sender
    based on their unique identity material (id + password_hash + salt).
    The key never leaves the server-side session context.
    """
    identity_material = f"{user.id}:{user.password_hash}:{user.salt}".encode("utf-8")
    return streebog512(identity_material)[:32]


# ---------------------------------------------------------------------------
# Kuznyechik CBC symmetric encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message_kuznyechik(
    body_bytes: bytes,
    enc_key: bytes,
    passphrase_hint: bool = False,
) -> Tuple[str, str]:
    """
    GOST R 34.12-2015 Kuznyechik CBC block encryption with PKCS#7 padding and HMAC-Streebog-512.
    Key must be provided externally (derived from passphrase or personal key).
    Returns (ciphertext_b64, key_bundle_json).
    """
    iv = os.urandom(16)
    salt = os.urandom(32)

    kuz = Kuznyechik(enc_key)
    enc_data = kuz.encrypt_cbc(body_bytes, iv=iv)
    ct = enc_data[16:]  # skip IV prefix

    hmac_tag = hmac_streebog512(enc_key, iv + ct)

    bundle = {
        "alg": "KUZNYECHIK-256",
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "hmac": base64.b64encode(hmac_tag).decode("ascii"),
        # passphrase_protected=true means recipient must supply the same passphrase
        # passphrase_protected=false means recipient uses their own personal key
        "passphrase_protected": passphrase_hint,
    }

    return base64.b64encode(ct).decode("ascii"), json.dumps(bundle)


def decrypt_message_kuznyechik(
    ciphertext_b64: str,
    bundle_json: str,
    enc_key: bytes,
) -> bytes:
    """Decrypts a Kuznyechik CBC ciphertext using the provided symmetric key."""
    bundle = json.loads(bundle_json)
    iv = base64.b64decode(bundle["iv"])
    ct = base64.b64decode(ciphertext_b64)

    if "hmac" in bundle:
        expected_hmac = base64.b64decode(bundle["hmac"])
        calc_hmac = hmac_streebog512(enc_key, iv + ct)
        if not hmac.compare_digest(calc_hmac, expected_hmac):
            raise ValueError("Kuznyechik-256 HMAC integrity verification failed!")

    kuz = Kuznyechik(enc_key)
    return kuz.decrypt_cbc(iv + ct)


# ---------------------------------------------------------------------------
# Public send_message API
# ---------------------------------------------------------------------------

def send_message(
    db: Session,
    sender: User,
    recipient_id: int,
    subject: str,
    body: str,
    encryption_type: str = "RSA-4096",
    kuz_passphrase: Optional[str] = None,
    sign_ecp: bool = True,
    custom_p: Optional[str] = None,
    custom_q: Optional[str] = None,
    **kwargs,
) -> Tuple[Optional[Message], Optional[str]]:
    """
    Composes, signs with sender's ЭЦП, encrypts with chosen algorithm
    (RSA hybrid or KUZNYECHIK-256 symmetric), and stores in the database.
    """
    if getattr(sender, "role", "") == "guest" or getattr(sender, "is_guest", False):
        return None, "Пользователи с рангом «Гость» не имеют прав на отправку сообщений."

    recipient = db.query(User).filter(User.id == recipient_id).first()
    if not recipient:
        return None, "Получатель не найден."

    body_bytes = body.encode("utf-8")

    # 1. Sign plaintext with sender's self-issued ECP (Digital Signature)
    ecp_sig = ""
    if sign_ecp and sender.ecp_private_key:
        try:
            priv_ecp = load_ecp_private_key_pem(sender.ecp_private_key)
            ecp_sig = sign_message(priv_ecp, body_bytes)
        except Exception as e:
            return None, f"Ошибка при наложении ЭЦП: {e}"

    # 2. Encrypt according to selected algorithm
    enc_type_upper = encryption_type.upper()
    if "RSA" in enc_type_upper:
        # RSA hybrid envelope encryption (2048, 4096, 8192, 32768 bits)
        rec_rsa_pub_pem = recipient.rsa_public_key
        if not rec_rsa_pub_pem:
            return None, "У получателя отсутствует открытый ключ RSA."
        try:
            rsa_pub = load_public_key_pem(rec_rsa_pub_pem)
            bundle_str = rsa_encrypt_hybrid(rsa_pub, body_bytes)
            parsed_bundle = json.loads(bundle_str)
            ciphertext_val = parsed_bundle["ciphertext"]
            key_bundle_val = bundle_str
            # Record key size in algorithm tag
            key_bits = rsa_pub.key_size
            if "32K" in enc_type_upper or key_bits >= 32768:
                final_alg = "RSA-32K"
            elif enc_type_upper.startswith("RSA-"):
                final_alg = enc_type_upper
            else:
                final_alg = f"RSA-{key_bits}"
        except Exception as e:
            return None, f"Ошибка RSA шифрования: {e}"

    elif "KUZNYECHIK" in enc_type_upper or "КУЗНЕЧИК" in enc_type_upper:
        # Kuznyechik 256-bit symmetric block encryption — NO ECDH
        try:
            if kuz_passphrase and kuz_passphrase.strip():
                # Passphrase-based key — the passphrase must be shared with the recipient OOB
                passphrase_salt = os.urandom(32)
                enc_key = _derive_kuznyechik_key_from_passphrase(kuz_passphrase.strip(), passphrase_salt)
                ciphertext_val, key_bundle_val = encrypt_message_kuznyechik(
                    body_bytes, enc_key, passphrase_hint=True
                )
                # Inject the passphrase derivation salt into the bundle
                bundle_obj = json.loads(key_bundle_val)
                bundle_obj["passphrase_salt"] = base64.b64encode(passphrase_salt).decode("ascii")
                key_bundle_val = json.dumps(bundle_obj)
            else:
                # Personal symmetric key derived deterministically from sender's identity material
                enc_key = _derive_personal_kuznyechik_key(sender)
                ciphertext_val, key_bundle_val = encrypt_message_kuznyechik(
                    body_bytes, enc_key, passphrase_hint=False
                )
                # Store sender id so the recipient/admin can identify the key owner
                bundle_obj = json.loads(key_bundle_val)
                bundle_obj["key_owner_id"] = sender.id
                key_bundle_val = json.dumps(bundle_obj)
            final_alg = "KUZNYECHIK-256"
        except Exception as e:
            return None, f"Ошибка шифрования Кузнечик: {e}"

    else:
        return None, f"Неизвестный тип шифрования: {encryption_type}"

    # 3. Save message into database (fields are encrypted at rest with Kuznyechik)
    msg = Message(
        sender_id=sender.id,
        recipient_id=recipient.id,
        encryption_type=final_alg,
        ecp_signature=ecp_sig if ecp_sig else None,
        ecp_cert_snapshot=sender.ecp_certificate if (sign_ecp and sender.ecp_certificate) else None,
    )
    msg.subject = subject
    msg.ciphertext = ciphertext_val
    msg.key_bundle = key_bundle_val

    db.add(msg)
    db.commit()
    db.refresh(msg)

    return msg, None


def decrypt_message_content(
    db: Session,
    message: Message,
    user: Optional[User] = None,
    kuz_passphrase: Optional[str] = None,
    current_user: Optional[User] = None,
) -> Tuple[Optional[str], bool, str, Optional[Dict[str, Any]]]:
    """
    Decrypts the message content.
    Returns (decrypted_body, is_signature_valid, signature_status_message, cert_details).
    Accessible by sender, recipient, or admin.

    For KUZNYECHIK-256:
      - If the bundle indicates passphrase protection, kuz_passphrase must be supplied.
      - Otherwise, the sender's personal key is re-derived from their identity material.
    """
    effective_user = user or current_user
    if effective_user is None:
        return None, False, "Пользователь не указан.", None

    is_admin = effective_user.role == "admin"
    is_recipient = effective_user.id == message.recipient_id
    is_sender = effective_user.id == message.sender_id

    if not (is_admin or is_recipient or is_sender):
        return None, False, "Доступ запрещен.", None

    decrypted_bytes = None

    if message.encryption_type.startswith("RSA"):
        # Needs recipient's RSA private key
        recipient = db.query(User).filter(User.id == message.recipient_id).first()
        if recipient and recipient.rsa_private_key:
            try:
                priv_rsa = load_private_key_pem(recipient.rsa_private_key)
                decrypted_bytes = rsa_decrypt_hybrid(priv_rsa, message.key_bundle)
            except Exception as e:
                return None, False, f"Ошибка RSA расшифрования: {e}", None
        else:
            return None, False, "Ключ расшифрования RSA недоступен.", None

    elif message.encryption_type == "KUZNYECHIK-256":
        try:
            bundle = json.loads(message.key_bundle)
        except Exception:
            return None, False, "Ошибка чтения пакета ключа Кузнечик.", None

        is_passphrase_protected = bundle.get("passphrase_protected", False)

        if is_passphrase_protected:
            # Re-derive key from passphrase
            if not kuz_passphrase or not kuz_passphrase.strip():
                return None, False, "Для расшифрования этого сообщения требуется кодовая фраза.", None
            passphrase_salt_b64 = bundle.get("passphrase_salt")
            if not passphrase_salt_b64:
                return None, False, "Отсутствует соль кодовой фразы в пакете ключа.", None
            passphrase_salt = base64.b64decode(passphrase_salt_b64)
            enc_key = _derive_kuznyechik_key_from_passphrase(kuz_passphrase.strip(), passphrase_salt)
        else:
            # Re-derive from sender's personal key material
            key_owner_id = bundle.get("key_owner_id", message.sender_id)
            key_owner = db.query(User).filter(User.id == key_owner_id).first()
            if not key_owner:
                return None, False, "Владелец персонального ключа Кузнечик не найден.", None
            enc_key = _derive_personal_kuznyechik_key(key_owner)

        try:
            decrypted_bytes = decrypt_message_kuznyechik(
                message.ciphertext, message.key_bundle, enc_key
            )
        except ValueError as e:
            return None, False, f"Ошибка расшифрования Кузнечик: {e}", None
        except Exception as e:
            return None, False, f"Ошибка расшифрования Кузнечик: {e}", None

    if decrypted_bytes is None:
        return None, False, "Не удалось расшифровать сообщение.", None

    decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")

    # Verify Digital Signature (ЭЦП)
    is_sig_valid = False
    sig_status = "ЭЦП отсутствует"
    if message.ecp_signature:
        sender = db.query(User).filter(User.id == message.sender_id).first()
        pub_pem = sender.ecp_public_key if sender else None
        if not pub_pem and message.ecp_cert_snapshot:
            try:
                cert = json.loads(message.ecp_cert_snapshot)
                cert_subj = cert.get("subject", {})
                if verify_certificate(cert) and cert_subj.get("user_id") == message.sender_id:
                    pub_pem = cert.get("public_key_pem")
                else:
                    sig_status = "Сертификат отправителя в снимке не прошел проверку подлинности или не принадлежит автору"
            except Exception:
                pass

        if pub_pem:
            try:
                pub_ecp = load_ecp_public_key_pem(pub_pem)
                is_sig_valid = verify_message_signature(pub_ecp, decrypted_bytes, message.ecp_signature)
                sig_status = "ЭЦП ПОДЛИННАЯ (ГОСТ Стрибог-512)" if is_sig_valid else "ЭЦП недействительна (сообщение изменено!)"
            except Exception as e:
                sig_status = f"Ошибка проверки ЭЦП: {e}"
        else:
            sig_status = "Открытый ключ ЭЦП отправителя не найден"

    cert_details = None
    if message.ecp_cert_snapshot:
        try:
            cert_details = json.loads(message.ecp_cert_snapshot)
        except Exception:
            pass
    if not cert_details:
        sender = db.query(User).filter(User.id == message.sender_id).first()
        if sender and sender.ecp_certificate:
            try:
                cert_details = json.loads(sender.ecp_certificate)
            except Exception:
                pass

    return decrypted_text, is_sig_valid, sig_status, cert_details
