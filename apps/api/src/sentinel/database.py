"""SQLAlchemy storage with pooled Neon URLs and local SQLite support."""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from .config import get_settings


class Base(DeclarativeBase):
    pass


def database_options(raw_url: str, *, serverless: bool = False):
    url = make_url(raw_url)
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")
    if serverless and url.get_backend_name() != "postgresql":
        raise RuntimeError("Vercel requires a persistent PostgreSQL DATABASE_URL")
    options = {"pool_pre_ping": True}
    if url.get_backend_name() == "sqlite":
        if url.database and url.database != ":memory:":
            Path(url.database).parent.mkdir(parents=True, exist_ok=True)
        options["connect_args"] = {"timeout": 30}
    elif url.drivername == "postgresql+psycopg":
        # Neon provides transaction pooling. Do not retain idle connections in
        # every function instance or create named prepared statements.
        options["poolclass"] = NullPool
        options["connect_args"] = {"prepare_threshold": None, "connect_timeout": 10}
    return url, options


settings = get_settings()
_url, _options = database_options(settings.database_url, serverless=settings.vercel)
engine = create_engine(_url, **_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Initialize an empty database explicitly before the first cloud deployment."""
    from . import models  # noqa: F401

    schema_engine = engine
    if settings.database_url_unpooled:
        schema_url, schema_options = database_options(settings.database_url_unpooled)
        schema_engine = create_engine(schema_url, **schema_options)
    with schema_engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            from sqlalchemy import text
            # Serialize first-time schema creation across concurrent setup jobs.
            connection.execute(text("SELECT pg_advisory_xact_lock(736368420)"))
        Base.metadata.create_all(connection)
    if schema_engine is not engine:
        schema_engine.dispose()


def get_db():
    with SessionLocal() as db:
        yield db
