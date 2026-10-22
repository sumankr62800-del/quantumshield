from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEvent


def log_security_event(
    db: Session,
    event_type: str,
    severity: str = "LOW",
    description: str | None = None,
    user_id: int | None = None,
    ip_address: str | None = None,
):
    event = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        description=description,
        ip_address=ip_address,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event