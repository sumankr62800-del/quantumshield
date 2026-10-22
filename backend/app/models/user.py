from sqlalchemy import Column, Integer, String, Boolean, Text

from backend.app.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String(50),
        unique=True,
        nullable=False,
    )

    email = Column(
        String(100),
        unique=True,
        nullable=False,
    )

    hashed_password = Column(
        String(255),
        nullable=False,
    )

    is_active = Column(
        Boolean,
        default=True,
    )

    pqc_public_key = Column(
        Text,
        nullable=True,
    )

    pqc_private_key = Column(
        Text,
        nullable=True,
    )