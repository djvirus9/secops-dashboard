from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os

def get_database_url() -> URL:
    """Keep database credentials structured so reserved characters stay literal."""
    if os.environ.get("DATABASE_URL"):
        return make_url(os.environ["DATABASE_URL"])
    if os.environ.get("PGHOST"):
        try:
            port = int(os.environ.get("PGPORT", "5432"))
        except ValueError as exc:
            raise ValueError("PGPORT must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("PGPORT must be between 1 and 65535")
        return URL.create(
            "postgresql+psycopg2",
            username=os.environ.get("PGUSER", "secops"),
            password=os.environ.get("PGPASSWORD"),
            host=os.environ["PGHOST"],
            port=port,
            database=os.environ.get("PGDATABASE", "secops"),
        )
    return make_url("sqlite:///./secops.db")


DATABASE_URL = get_database_url()

connect_args = {}
if DATABASE_URL.get_backend_name() == "sqlite":
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass
