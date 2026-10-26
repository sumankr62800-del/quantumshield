
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
)

from backend.app.database.connection import Base


class Message(Base):
    __tablename__ = "messages"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # --------------------------------------------------------
    # MESSAGE SENDER
    # --------------------------------------------------------

    sender_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # --------------------------------------------------------
    # MESSAGE RECEIVER
    # --------------------------------------------------------

    receiver_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # --------------------------------------------------------
    # OLD PQC FIELD
    # --------------------------------------------------------
    # Kept for backward compatibility with existing messages.

    kem_ciphertext = Column(
        Text,
        nullable=True,
    )

    # --------------------------------------------------------
    # NEW PQC FIELDS
    # --------------------------------------------------------
    # Separate ML-KEM ciphertext for sender and receiver.

    sender_kem_ciphertext = Column(
        Text,
        nullable=True,
    )

    receiver_kem_ciphertext = Column(
        Text,
        nullable=True,
    )

    # --------------------------------------------------------
    # AES-GCM ENCRYPTED MESSAGE
    # --------------------------------------------------------

    ciphertext = Column(
        Text,
        nullable=False,
    )

    nonce = Column(
        String(24),
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
