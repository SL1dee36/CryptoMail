# Description: SQLAlchemy User model with Role-Based Access Control (RBAC), 3FA, and encrypted key storage.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import datetime
import json
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from database import Base
from crypto.db_cipher import decrypt_db_field, encrypt_db_field


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    
    # Password hashed with GOST R 34.11-2012 Streebog-512 + Salt
    password_hash = Column(String(128), nullable=False)
    salt = Column(String(64), nullable=False)

    # Roles: 'guest', 'user', 'admin'
    role = Column(String(20), default="user", nullable=False)

    # 3FA state
    is_3fa_enabled = Column(Boolean, default=True)
    totp_secret = Column(String(64), nullable=True)  # Base32 secret
    
    # Encrypted fields (Encrypted at rest with GOST Kuznyechik)
    _recovery_codes = Column("recovery_codes", Text, nullable=True)
    _ecp_private_key_enc = Column("ecp_private_key_enc", Text, nullable=True)
    _rsa_private_key_enc = Column("rsa_private_key_enc", Text, nullable=True)

    # Public cryptographic materials
    ecp_public_key = Column(Text, nullable=True)
    ecp_certificate = Column(Text, nullable=True)  # JSON serialized self-issued cert
    rsa_public_key = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Kuznyechik-encrypted property accessors
    @property
    def recovery_codes_list(self):
        dec = decrypt_db_field(self._recovery_codes)
        if not dec:
            return []
        try:
            return json.loads(dec)
        except Exception:
            return dec.split(",")

    @recovery_codes_list.setter
    def recovery_codes_list(self, codes):
        if codes is None:
            self._recovery_codes = None
        else:
            json_str = json.dumps(codes) if isinstance(codes, list) else str(codes)
            self._recovery_codes = encrypt_db_field(json_str)

    @property
    def ecp_private_key(self):
        return decrypt_db_field(self._ecp_private_key_enc)

    @ecp_private_key.setter
    def ecp_private_key(self, pem_str):
        self._ecp_private_key_enc = encrypt_db_field(pem_str)

    @property
    def rsa_private_key(self):
        return decrypt_db_field(self._rsa_private_key_enc)

    @rsa_private_key.setter
    def rsa_private_key(self, pem_str):
        self._rsa_private_key_enc = encrypt_db_field(pem_str)

    @property
    def role_title_ru(self) -> str:
        mapping = {
            "guest": "Гость",
            "user": "Пользователь",
            "admin": "Админ",
        }
        return mapping.get(self.role, self.role)
