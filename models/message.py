# Description: SQLAlchemy Message model with ciphertext envelope, digital signature, and certificate snapshot.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from database import Base
from crypto.db_cipher import decrypt_db_field, encrypt_db_field


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Encryption type selected by sender: 'RSA-32K' or 'STREEBOG-512'
    encryption_type = Column(String(30), nullable=False)

    # Database-encrypted fields (Encrypted at rest with GOST Kuznyechik)
    _subject_enc = Column("subject_enc", Text, nullable=False)
    _ciphertext_enc = Column("ciphertext_enc", Text, nullable=False)
    _key_bundle_enc = Column("key_bundle_enc", Text, nullable=True)

    # Digital Signature (ЭЦП) and Certificate
    ecp_signature = Column(Text, nullable=True)
    ecp_cert_snapshot = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])

    # Kuznyechik-encrypted property accessors
    @property
    def subject(self) -> str:
        return decrypt_db_field(self._subject_enc) or ""

    @subject.setter
    def subject(self, value: str):
        self._subject_enc = encrypt_db_field(value)

    @property
    def ciphertext(self) -> str:
        """The message payload encrypted by RSA-32K or Streebog-512."""
        return decrypt_db_field(self._ciphertext_enc) or ""

    @ciphertext.setter
    def ciphertext(self, value: str):
        self._ciphertext_enc = encrypt_db_field(value)

    @property
    def key_bundle(self) -> str:
        return decrypt_db_field(self._key_bundle_enc) or ""

    @key_bundle.setter
    def key_bundle(self, value: str):
        self._key_bundle_enc = encrypt_db_field(value)
