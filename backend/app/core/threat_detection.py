from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEvent


# ============================================================
# RISK CONFIGURATION
# ============================================================

EVENT_SCORES = {
    "LOGIN_FAILED": 15,
    "LOGIN_SUCCESS": 0,
    "USER_REGISTERED": 0,

    # Messaging / cryptographic security events
    "MESSAGE_DECRYPTION_FAILED": 25,
    "KEM_TAMPERING": 40,
    "CIPHERTEXT_TAMPERING": 40,
    "INVALID_TOKEN": 20,
    "UNAUTHORIZED_ACCESS": 25,
}

DEFAULT_EVENT_SCORE = 5


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:
    """
    Convert a numeric risk score into a threat level.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# ============================================================
# USER RISK ANALYSIS
# ============================================================

def calculate_user_risk(
    db: Session,
    user_id: int,
    window_minutes: int = 60,
) -> dict:
    """
    Calculate the current security risk for a user.

    Only events associated with the supplied user_id are
    considered.

    Returns:
        {
            "user_id": int,
            "risk_score": int,
            "risk_level": str,
            "event_count": int,
            "failed_logins": int,
            "critical_events": int,
            "events": [...]
        }
    """

    since = datetime.now(timezone.utc).replace(
        tzinfo=None
    ) - timedelta(minutes=window_minutes)

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.created_at >= since,
        )
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )

    score = 0
    failed_logins = 0
    critical_events = 0

    event_summary = Counter()

    for event in events:

        event_type = event.event_type

        event_summary[event_type] += 1

        score += EVENT_SCORES.get(
            event_type,
            DEFAULT_EVENT_SCORE,
        )

        if event_type == "LOGIN_FAILED":
            failed_logins += 1

        if event.severity == "CRITICAL":
            critical_events += 1

    # --------------------------------------------------------
    # Brute-force detection
    # --------------------------------------------------------

    if failed_logins >= 3:
        score += 15

    if failed_logins >= 5:
        score += 20

    # --------------------------------------------------------
    # Critical event escalation
    # --------------------------------------------------------

    if critical_events > 0:
        score += 25

    # --------------------------------------------------------
    # Maximum risk score
    # --------------------------------------------------------

    score = min(score, 100)

    return {
        "user_id": user_id,
        "risk_score": score,
        "risk_level": get_risk_level(score),
        "event_count": len(events),
        "failed_logins": failed_logins,
        "critical_events": critical_events,
        "event_summary": dict(event_summary),
        "window_minutes": window_minutes,
    }


# ============================================================
# GLOBAL SECURITY ANALYSIS
# ============================================================

def calculate_global_risk(
    db: Session,
    window_minutes: int = 60,
) -> dict:
    """
    Calculate security activity across the entire system.
    """

    since = datetime.now(timezone.utc).replace(
        tzinfo=None
    ) - timedelta(minutes=window_minutes)

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.created_at >= since
        )
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )

    score = 0
    failed_logins = 0
    critical_events = 0

    event_summary = Counter()

    for event in events:

        event_type = event.event_type

        event_summary[event_type] += 1

        score += EVENT_SCORES.get(
            event_type,
            DEFAULT_EVENT_SCORE,
        )

        if event_type == "LOGIN_FAILED":
            failed_logins += 1

        if event.severity == "CRITICAL":
            critical_events += 1

    # --------------------------------------------------------
    # Global brute-force activity
    # --------------------------------------------------------

    if failed_logins >= 5:
        score += 20

    if failed_logins >= 10:
        score += 30

    if critical_events > 0:
        score += 25

    score = min(score, 100)

    return {
        "risk_score": score,
        "risk_level": get_risk_level(score),
        "event_count": len(events),
        "failed_logins": failed_logins,
        "critical_events": critical_events,
        "event_summary": dict(event_summary),
        "window_minutes": window_minutes,
    }