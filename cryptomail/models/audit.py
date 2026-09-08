# Description: Security audit log entity for administrative oversight.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text
from cryptomail.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    username = Column(String(50), nullable=True)
    ip_address = Column(String(50), nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event='{self.event_type}' user='{self.username}'>"
