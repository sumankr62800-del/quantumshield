from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text

from backend.app.database.connection import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, nullable=True, index=True)

    event_type = Column(String(100), nullable=False, index=True)

    severity = Column(String(20), nullable=False, default="LOW")

    description = Column(Text, nullable=True)

    ip_address = Column(String(45), nullable=True)

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )