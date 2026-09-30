"""Database initialization for the MVP schema."""

from sqlalchemy.engine import Engine
from app.db.base import Base
from app.models import incident, review  # noqa: F401


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)
