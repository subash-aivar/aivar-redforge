"""SQLAlchemy declarative base for all database models.

All ORM models must inherit from Base. This ensures consistent
metadata, naming conventions, and a single registry for Alembic.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Naming convention ensures predictable constraint names across all databases,
# which is critical for Alembic auto-generated migrations.
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models.

    Uses DeclarativeBase for modern SQLAlchemy 2.x mapped column syntax.
    All models inherit from this class and are automatically registered
    for Alembic migrations.
    """

    metadata = MetaData(naming_convention=convention)
