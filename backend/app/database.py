import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Resolve SQLite database file path
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'usb_forensics.db'}")

# SQLite specific connect args (check_same_thread=False for FastAPI multi-threaded requests)
engine = create_engine(
    DB_PATH,
    connect_args={"check_same_thread": False} if DB_PATH.startswith("sqlite") else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for providing a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
