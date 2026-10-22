from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEvent


# ============================================================
# SECURITY EVENT FEATURES
# ============================================================

EVENT_TYPES = [
    "LOGIN_FAILED",
    "LOGIN_SUCCESS",
    "USER_REGISTERED",
    "MESSAGE_DECRYPTION_FAILED",
    "KEM_TAMPERING",
    "CIPHERTEXT_TAMPERING",
    "INVALID_TOKEN",
    "UNAUTHORIZED_ACCESS",
]


def extract_user_features(
    db: Session,
    user_id: int,
    window_minutes: int = 60,
) -> dict:
    """
    Convert a user's recent security events into
    numerical ML features.
    """

    since = (
        datetime.now(timezone.utc)
        .replace(tzinfo=None)
        - timedelta(minutes=window_minutes)
    )

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.created_at >= since,
        )
        .all()
    )

    features = {}

    # --------------------------------------------------------
    # Event counts
    # --------------------------------------------------------

    for event_type in EVENT_TYPES:
        key = event_type.lower() + "_count"

        features[key] = sum(
            1
            for event in events
            if event.event_type == event_type
        )

    # --------------------------------------------------------
    # Severity counts
    # --------------------------------------------------------

    features["low_event_count"] = sum(
        1
        for event in events
        if event.severity == "LOW"
    )

    features["medium_event_count"] = sum(
        1
        for event in events
        if event.severity == "MEDIUM"
    )

    features["high_event_count"] = sum(
        1
        for event in events
        if event.severity == "HIGH"
    )

    features["critical_event_count"] = sum(
        1
        for event in events
        if event.severity == "CRITICAL"
    )

    # --------------------------------------------------------
    # Total activity
    # --------------------------------------------------------

    features["total_events"] = len(events)

    features["event_rate"] = (
        len(events) / window_minutes
        if window_minutes > 0
        else 0
    )

    # --------------------------------------------------------
    # Failed login ratio
    # --------------------------------------------------------

    failed_logins = features["login_failed_count"]

    total_logins = (
        failed_logins
        + features["login_success_count"]
    )

    features["failed_login_ratio"] = (
        failed_logins / total_logins
        if total_logins > 0
        else 0
    )

    # --------------------------------------------------------
    # Cryptographic attack activity
    # --------------------------------------------------------

    features["crypto_attack_count"] = (
        features["kem_tampering_count"]
        + features["ciphertext_tampering_count"]
        + features["message_decryption_failed_count"]
    )

    # --------------------------------------------------------
    # Authentication attack activity
    # --------------------------------------------------------

    features["authentication_attack_count"] = (
        features["login_failed_count"]
        + features["invalid_token_count"]
        + features["unauthorized_access_count"]
    )

    return features


def extract_global_features(
    db: Session,
    window_minutes: int = 60,
) -> dict:
    """
    Convert global security activity into
    numerical ML features.
    """

    since = (
        datetime.now(timezone.utc)
        .replace(tzinfo=None)
        - timedelta(minutes=window_minutes)
    )

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.created_at >= since
        )
        .all()
    )

    features = {}

    # --------------------------------------------------------
    # Event counts
    # --------------------------------------------------------

    for event_type in EVENT_TYPES:
        key = event_type.lower() + "_count"

        features[key] = sum(
            1
            for event in events
            if event.event_type == event_type
        )

    # --------------------------------------------------------
    # Severity counts
    # --------------------------------------------------------

    features["low_event_count"] = sum(
        1
        for event in events
        if event.severity == "LOW"
    )

    features["medium_event_count"] = sum(
        1
        for event in events
        if event.severity == "MEDIUM"
    )

    features["high_event_count"] = sum(
        1
        for event in events
        if event.severity == "HIGH"
    )

    features["critical_event_count"] = sum(
        1
        for event in events
        if event.severity == "CRITICAL"
    )

    # --------------------------------------------------------
    # Total activity
    # --------------------------------------------------------

    features["total_events"] = len(events)

    features["event_rate"] = (
        len(events) / window_minutes
        if window_minutes > 0
        else 0
    )

    # --------------------------------------------------------
    # Failed login ratio
    # --------------------------------------------------------

    failed_logins = features["login_failed_count"]

    total_logins = (
        failed_logins
        + features["login_success_count"]
    )

    features["failed_login_ratio"] = (
        failed_logins / total_logins
        if total_logins > 0
        else 0
    )

    # --------------------------------------------------------
    # Cryptographic attack activity
    # --------------------------------------------------------

    features["crypto_attack_count"] = (
        features["kem_tampering_count"]
        + features["ciphertext_tampering_count"]
        + features["message_decryption_failed_count"]
    )

    # --------------------------------------------------------
    # Authentication attack activity
    # --------------------------------------------------------

    features["authentication_attack_count"] = (
        features["login_failed_count"]
        + features["invalid_token_count"]
        + features["unauthorized_access_count"]
    )

    return features