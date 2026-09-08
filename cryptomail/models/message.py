# Description: Message entity with hybrid encrypted payload, ECP signature and DB encryption.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from cryptomail.database import Base, EncryptedString, EncryptedText


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Content encrypted transparently at rest using GOST Kuznyechik
    subject = Column(EncryptedString, nullable=False)
    ciphertext = Column(EncryptedText, nullable=False)

    # Encryption specification: RSA-2048, RSA-4096, RSA-8192, RSA-32768, KUZNYECHIK-256
    encryption_type = Column(String(30), nullable=False)
    key_bundle = Column(EncryptedText, nullable=True)

    # GOST R 34.10-2012 Digital Signature & Certificate snapshot
    ecp_signature = Column(Text, nullable=True)
    ecp_cert_snapshot = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)

    sender = relationship("User", foreign_keys=[sender_id], lazy="joined")
    recipient = relationship("User", foreign_keys=[recipient_id], lazy="joined")

    def __repr__(self) -> str:
        return f"<Message id={self.id} from={self.sender_id} to={self.recipient_id} type={self.encryption_type}>"
