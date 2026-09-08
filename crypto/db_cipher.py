# Description: Transparent database encryption layer using GOST Kuznyechik block cipher in CBC mode.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import os
from typing import Optional, Union
from crypto.kuznyechik import Kuznyechik

# Master key for transparent database encryption
_DEFAULT_DB_KEY_HEX = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"

def _load_or_create_db_key() -> bytes:
    env_key = os.environ.get("DB_MASTER_KEY_HEX")
    if env_key:
        return bytes.fromhex(env_key)
    key_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
    )
    key_file = os.path.join(key_dir, ".db_master.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return bytes.fromhex(content)
        except Exception:
            pass

    # Automatically generate a unique random 256-bit key and persist it
    try:
        os.makedirs(key_dir, exist_ok=True)
        new_key = os.urandom(32)
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(new_key.hex())
        return new_key
    except Exception:
        # Graceful fallback if filesystem is read-only
        return bytes.fromhex(_DEFAULT_DB_KEY_HEX)

_DB_MASTER_KEY = _load_or_create_db_key()
_cipher = Kuznyechik(_DB_MASTER_KEY)


def encrypt_db_field(value: Optional[Union[str, bytes]]) -> Optional[str]:
    """Encrypts plaintext string/bytes using Kuznyechik CBC. Returns base64 encoded string."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.encode("utf-8")
    enc = _cipher.encrypt_cbc(value)
    return base64.b64encode(enc).decode("ascii")


def decrypt_db_field(enc_value: Optional[str]) -> Optional[str]:
    """Decrypts base64 Kuznyechik CBC ciphertext back into utf-8 string."""
    if enc_value is None:
        return None
    data = base64.b64decode(enc_value)
    try:
        dec = _cipher.decrypt_cbc(data)
    except Exception:
        # Backward compatibility fallback for records created before key persistence
        try:
            legacy_cipher = Kuznyechik(bytes.fromhex(_DEFAULT_DB_KEY_HEX))
            dec = legacy_cipher.decrypt_cbc(data)
        except Exception:
            raise
    return dec.decode("utf-8", errors="replace")


def encrypt_db_bytes(value: Optional[bytes]) -> Optional[bytes]:
    if value is None:
        return None
    return _cipher.encrypt_cbc(value)


def decrypt_db_bytes(enc_value: Optional[bytes]) -> Optional[bytes]:
    if enc_value is None:
        return None
    try:
        return _cipher.decrypt_cbc(enc_value)
    except Exception:
        try:
            legacy_cipher = Kuznyechik(bytes.fromhex(_DEFAULT_DB_KEY_HEX))
            return legacy_cipher.decrypt_cbc(enc_value)
        except Exception:
            raise
