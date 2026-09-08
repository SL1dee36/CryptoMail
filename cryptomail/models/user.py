# Description: User entity with RBAC roles, encrypted cryptographic keys and credentials.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

from datetime import datetime
import json
from typing import List, Optional
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from cryptomail.database import Base, EncryptedString, EncryptedText


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    salt = Column(String(64), nullable=False)

    # Role-based access control: 'guest', 'user', 'admin'
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # RSA keypair (private key encrypted at rest via Kuznyechik)
    rsa_public_key = Column(Text, nullable=True)
    rsa_private_key = Column(EncryptedText, nullable=True)
    rsa_key_size = Column(Integer, default=4096, nullable=False)

    # GOST R 34.10-2012 Digital Signature (ECP) & Self-Issued Certificate
    ecp_public_key = Column(Text, nullable=True)
    ecp_private_key = Column(EncryptedText, nullable=True)
    ecp_certificate = Column(Text, nullable=True)

    # 3FA credentials encrypted at rest via Kuznyechik
    totp_secret = Column(EncryptedString, nullable=True)
    recovery_codes = Column(EncryptedText, nullable=True)
    one_time_access_code = Column(EncryptedString, nullable=True)

    @property
    def is_guest(self) -> bool:
        return self.role == "guest"

    @property
    def is_user(self) -> bool:
        return self.role == "user"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def role_title_ru(self) -> str:
        roles = {
            "admin": "Администратор",
            "user": "Пользователь",
            "guest": "Гость",
        }
        return roles.get(self.role, self.role.capitalize())

    @property
    def is_3fa_enabled(self) -> bool:
        return True

    @is_3fa_enabled.setter
    def is_3fa_enabled(self, val: bool) -> None:
        pass

    @property
    def recovery_codes_list(self) -> List[str]:
        if not self.recovery_codes:
            return []
        try:
            return json.loads(self.recovery_codes)
        except Exception:
            return [c.strip() for c in self.recovery_codes.splitlines() if c.strip()]

    @recovery_codes_list.setter
    def recovery_codes_list(self, codes: List[str]) -> None:
        self.recovery_codes = json.dumps(codes)

    def consume_recovery_code(self, code: str) -> bool:
        """Consumes a one-time recovery code, removing it from the list."""
        clean_code = code.strip().upper().replace(" ", "").replace("-", "")
        current = self.recovery_codes_list
        for c in current:
            norm_c = c.strip().upper().replace(" ", "").replace("-", "")
            if norm_c == clean_code:
                current.remove(c)
                self.recovery_codes_list = current
                return True
        return False

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
