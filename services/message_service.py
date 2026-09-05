# Description: Message delivery service handling hybrid encryption, digital signing, decryption, and verification.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import json
import os
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session
from crypto.ecp import (
    load_ecp_private_key_pem,
    load_ecp_public_key_pem,
    sign_message,
    verify_message_signature,
)
from crypto.kuznyechik import Kuznyechik
from crypto.rsa32k import (
    load_private_key_pem,
    load_public_key_pem,
    rsa_decrypt_hybrid,
    rsa_encrypt_hybrid,
)
from crypto.streebog import hmac_streebog512, pbkdf2_streebog512
from models.message import Message
from models.user import User


def encrypt_message_streebog(body_bytes: bytes) -> Tuple[str, str]:
    """
    Authenticated stream encryption using GOST R 34.11-2012 Streebog-512 + Kuznyechik CTR.
    1. Generates 32-byte salt and 16-byte IV.
    2. Derives 256-bit encryption key using PBKDF2-Streebog-512.
    3. Encrypts body with Kuznyechik CTR.
    4. Computes HMAC-Streebog-512 integrity tag.
    Returns (ciphertext_b64, key_bundle_json).
    """
    salt = os.urandom(32)
    iv = os.urandom(16)
    enc_key = pbkdf2_streebog512(salt, salt, iterations=100, dklen=32)

    kuz = Kuznyechik(enc_key)
    enc_data = kuz.encrypt_ctr(body_bytes, iv=iv)
    ct = enc_data[16:]  # skip IV prefix

    hmac_tag = hmac_streebog512(enc_key, iv + ct)

    bundle = {
        "alg": "STREEBOG-512",
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "hmac": base64.b64encode(hmac_tag).decode("ascii"),
    }
    return base64.b64encode(ct).decode("ascii"), json.dumps(bundle)


def decrypt_message_streebog(ciphertext_b64: str, bundle_json: str) -> bytes:
    """Decrypts message encrypted with Streebog-512 authenticated mode."""
    bundle = json.loads(bundle_json)
    salt = base64.b64decode(bundle["salt"])
    iv = base64.b64decode(bundle["iv"])
    expected_hmac = base64.b64decode(bundle["hmac"])
    ct = base64.b64decode(ciphertext_b64)

    enc_key = pbkdf2_streebog512(salt, salt, iterations=100, dklen=32)
    calc_hmac = hmac_streebog512(enc_key, iv + ct)
    if calc_hmac != expected_hmac:
        raise ValueError("Streebog-512 HMAC integrity verification failed!")

    kuz = Kuznyechik(enc_key)
    return kuz.decrypt_ctr(iv + ct)


def encrypt_message_kuznyechik(body_bytes: bytes) -> Tuple[str, str]:
    """
    Direct GOST R 34.12-2015 Kuznyechik CBC symmetric block encryption with PKCS#7 padding.
    """
    key = os.urandom(32)
    iv = os.urandom(16)
    kuz = Kuznyechik(key)
    enc_data = kuz.encrypt_cbc(body_bytes, iv=iv)
    ct = enc_data[16:]  # skip IV prefix
    bundle = {
        "alg": "KUZNYECHIK-256",
        "key": base64.b64encode(key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }
    return base64.b64encode(ct).decode("ascii"), json.dumps(bundle)


def decrypt_message_kuznyechik(ciphertext_b64: str, bundle_json: str) -> bytes:
    """Decrypts message encrypted with direct Kuznyechik CBC mode."""
    bundle = json.loads(bundle_json)
    key = base64.b64decode(bundle["key"])
    iv = base64.b64decode(bundle["iv"])
    ct = base64.b64decode(ciphertext_b64)
    kuz = Kuznyechik(key)
    return kuz.decrypt_cbc(iv + ct)


def send_message(
    db: Session,
    sender: User,
    recipient_id: int,
    subject: str,
    body: str,
    encryption_type: str,
) -> Tuple[Optional[Message], Optional[str]]:
    """
    Composes, signs with sender's ЭЦП, encrypts with chosen algorithm
    (RSA-32K, RSA-4096, RSA-2048, STREEBOG-512, KUZNYECHIK-256),
    and stores in the database with Kuznyechik encryption at rest.
    """
    recipient = db.query(User).filter(User.id == recipient_id).first()
    if not recipient:
        return None, "Получатель не найден."

    if sender.role == "guest":
        return None, "Пользователи с рангом «Гость» имеют доступ только для чтения."

    body_bytes = body.encode("utf-8")

    # 1. Sign plaintext with sender's self-issued ECP (Digital Signature)
    ecp_sig = ""
    if sender.ecp_private_key:
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
    elif "STREEBOG" in enc_type_upper or "СТРИБОГ" in enc_type_upper:
        # Streebog-512 authenticated stream encryption
        try:
            ciphertext_val, key_bundle_val = encrypt_message_streebog(body_bytes)
            final_alg = "STREEBOG-512"
        except Exception as e:
            return None, f"Ошибка шифрования Стрибог-512: {e}"
    elif "KUZNYECHIK" in enc_type_upper or "КУЗНЕЧИК" in enc_type_upper:
        # Kuznyechik 256-bit symmetric block encryption
        try:
            ciphertext_val, key_bundle_val = encrypt_message_kuznyechik(body_bytes)
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
        ecp_signature=ecp_sig,
        ecp_cert_snapshot=sender.ecp_certificate,
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
    user: User,
) -> Tuple[Optional[str], bool, str]:
    """
    Decrypts the message content.
    Returns (decrypted_body, is_signature_valid, signature_status_message).
    Accessible by sender, recipient, or admin.
    """
    is_admin = user.role == "admin"
    is_recipient = user.id == message.recipient_id
    is_sender = user.id == message.sender_id

    if not (is_admin or is_recipient or is_sender):
        return None, False, "Доступ запрещен."

    decrypted_bytes = None

    if message.encryption_type.startswith("RSA"):
        # Needs recipient's RSA private key
        recipient = db.query(User).filter(User.id == message.recipient_id).first()
        if recipient and recipient.rsa_private_key:
            try:
                priv_rsa = load_private_key_pem(recipient.rsa_private_key)
                decrypted_bytes = rsa_decrypt_hybrid(priv_rsa, message.key_bundle)
            except Exception as e:
                return None, False, f"Ошибка RSA расшифрования: {e}"
        else:
            return None, False, "Ключ расшифрования RSA недоступен."

    elif message.encryption_type == "STREEBOG-512":
        try:
            decrypted_bytes = decrypt_message_streebog(message.ciphertext, message.key_bundle)
        except Exception as e:
            return None, False, f"Ошибка расшифрования Стрибог-512: {e}"

    elif message.encryption_type == "KUZNYECHIK-256":
        try:
            decrypted_bytes = decrypt_message_kuznyechik(message.ciphertext, message.key_bundle)
        except Exception as e:
            return None, False, f"Ошибка расшифрования Кузнечик: {e}"


    if decrypted_bytes is None:
        return None, False, "Не удалось расшифровать сообщение."

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
                pub_pem = cert.get("public_key_pem")
            except Exception:
                pass

        if pub_pem:
            try:
                pub_ecp = load_ecp_public_key_pem(pub_pem)
                is_sig_valid = verify_message_signature(pub_ecp, decrypted_bytes, message.ecp_signature)
                sig_status = "ЭЦП подтверждена (ГОСТ Стрибог-512)" if is_sig_valid else "ЭЦП недействительна (сообщение изменено!)"
            except Exception as e:
                sig_status = f"Ошибка проверки ЭЦП: {e}"
        else:
            sig_status = "Открытый ключ ЭЦП отправителя не найден"

    return decrypted_text, is_sig_valid, sig_status
