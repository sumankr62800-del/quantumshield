from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.core.security import get_current_user_id

from backend.app.core.threat_detection import (
    calculate_user_risk,
    calculate_global_risk,
)

from backend.app.ml.predict import (
    predict_user_threat,
    predict_global_threat,
)

from backend.app.models.security_event import SecurityEvent


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/security",
    tags=["Security"],
)


# ============================================================
# CURRENT USER RISK
# ============================================================

@router.get("/risk")
def get_my_risk(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return the rule-based security risk score
    for the authenticated user.
    """

    return calculate_user_risk(
        db=db,
        user_id=current_user_id,
    )


# ============================================================
# SECURITY EVENTS
# ============================================================

@router.get("/events")
def get_security_events(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return recent security events belonging only
    to the authenticated user.
    """

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id == current_user_id
        )
        .order_by(
            SecurityEvent.created_at.desc()
        )
        .limit(100)
        .all()
    )

    return [
        {
            "id": event.id,
            "user_id": event.user_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "ip_address": event.ip_address,
            "created_at": event.created_at,
        }
        for event in events
    ]


# ============================================================
# GLOBAL SECURITY STATUS
# ============================================================

@router.get("/status")
def get_security_status(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return the overall rule-based security status
    of the QuantumShield system.
    """

    return calculate_global_risk(
        db=db,
    )


# ============================================================
# ML THREAT DETECTION — CURRENT USER
# ============================================================

@router.get("/threat")
def get_my_threat_prediction(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Generate an ML-based threat prediction for
    the authenticated user.

    Uses:
        - Security event features
        - Trained Random Forest classifier
        - Threat probability
        - Threat score
        - Threat level
    """

    return predict_user_threat(
        db=db,
        user_id=current_user_id,
    )


# ============================================================
# ML THREAT DETECTION — GLOBAL
# ============================================================

@router.get("/threat/global")
def get_global_threat_prediction(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Generate an ML-based threat prediction for
    the entire QuantumShield system.
    """

    return predict_global_threat(
        db=db,
    )