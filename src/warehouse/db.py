"""
Database connection factory.
Reads credentials from .env and provides reusable engine + session helpers.
"""
import os
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def get_database_url() -> str:
    """Build PostgreSQL connection URL from .env values."""
    user = os.getenv("DB_USER")
    password = quote_plus(os.getenv("DB_PASSWORD") or "")
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    dbname = os.getenv("DB_NAME", "soc_sentinel")

    if not all([user, password, host, dbname]):
        missing = [k for k, v in {
            "DB_USER": user, "DB_PASSWORD": password,
            "DB_HOST": host, "DB_NAME": dbname
        }.items() if not v]
        raise ValueError(f"Missing required .env values: {missing}")

    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{dbname}"


# Singleton engine — reused across the project
_engine = None


def get_engine():
    """Return a singleton SQLAlchemy engine."""
    global _engine
    if _engine is None:
        _engine = create_engine(
            get_database_url(),
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,  # tests connection before use (handles dropped connections)
            echo=False,           # set True to debug SQL queries
        )
    return _engine


# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False)


@contextmanager
def get_session() -> Session:
    """
    Context manager for database sessions.

    Usage:
        with get_session() as session:
            users = session.query(DimUser).all()
    """
    session = SessionLocal(bind=get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def test_connection() -> bool:
    """Quick connection test."""
    from sqlalchemy import text
    try:
        with get_engine().connect() as conn:
            result = conn.execute(text("SELECT 1")).fetchone()
            return result[0] == 1
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False


if __name__ == "__main__":
    if test_connection():
        print(f"✅ Connected: {get_database_url().split('@')[1]}")