

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all Sentinel models."""


def _prepare_url(url: str) -> str:
    """Ensure the parent directory exists for file-backed SQLite URLs."""
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "", 1)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    return url


settings = get_settings()
_engine_kwargs = {}
if settings.database_url.startswith("sqlite"):
   
    _engine_kwargs["connect_args"] = {"timeout": 30}
engine = create_engine(_prepare_url(settings.database_url), echo=False, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create all tables. Called on app startup (sentinel.main)."""
    from . import models 

    Base.metadata.create_all(engine)


def get_db():
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
