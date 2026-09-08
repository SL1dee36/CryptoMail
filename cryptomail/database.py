# Description: Database connection, session management and transparent Kuznyechik field encryption.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import os
from typing import Any, Generator, Optional, Union
from sqlalchemy import TypeDecorator, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from crypto.db_cipher import encrypt_db_field, decrypt_db_field

# Root project path resolution
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "cryptomail.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class EncryptedString(TypeDecorator):
    """
    Transparently encrypts string data using GOST Kuznyechik in CBC mode
    before persisting to the database, and decrypts back upon loading.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Optional[Union[str, bytes]], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return encrypt_db_field(value)

    def process_result_value(self, value: Optional[str], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        return decrypt_db_field(value)


class EncryptedText(EncryptedString):
    """Alias for large text fields encrypted transparently with Kuznyechik CBC."""
    pass


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining database sessions in FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates all database tables defined in models."""
    import cryptomail.models.user  # noqa: F401
    import cryptomail.models.message  # noqa: F401
    import cryptomail.models.audit  # noqa: F401
    Base.metadata.create_all(bind=engine)
