# Description: Transparent database encryption layer using GOST Kuznyechik block cipher in CBC mode.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import os
from typing import Optional, Union
from crypto.kuznyechik import Kuznyechik

# Default master key for database encryption (in production, supplied via env var)
_DEFAULT_DB_KEY_HEX = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
_DB_MASTER_KEY = bytes.fromhex(os.environ.get("DB_MASTER_KEY_HEX", _DEFAULT_DB_KEY_HEX))

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
    dec = _cipher.decrypt_cbc(data)
    return dec.decode("utf-8", errors="replace")


def encrypt_db_bytes(value: Optional[bytes]) -> Optional[bytes]:
    if value is None:
        return None
    return _cipher.encrypt_cbc(value)


def decrypt_db_bytes(enc_value: Optional[bytes]) -> Optional[bytes]:
    if enc_value is None:
        return None
    return _cipher.decrypt_cbc(enc_value)
