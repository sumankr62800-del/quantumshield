from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.core.security import get_current_user_id

from backend.app.models.user import User
from backend.app.models.message import Message
from backend.app.models.security_event import SecurityEvent

from backend.app.core.threat_detection import (
    calculate_user_risk,
    calculate_global_risk,
)

from backend.app.ml.predict import (
    predict_user_threat,
    predict_global_threat,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


# ============================================================
# DASHBOARD OVERVIEW
# ============================================================

@router.get("/overview")
def get_dashboard_overview(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return the complete QuantumShield security dashboard.

    Includes:
        - User information
        - System statistics
        - Rule-based security risk
        - ML-based threat prediction
        - Recent security events
    """

    # --------------------------------------------------------
    # Current user
    # --------------------------------------------------------

    user = (
        db.query(User)
        .filter(User.id == current_user_id)
        .first()
    )

    # --------------------------------------------------------
    # System statistics
    # --------------------------------------------------------

    total_users = (
        db.query(func.count(User.id))
        .scalar()
        or 0
    )

    total_messages = (
        db.query(func.count(Message.id))
        .scalar()
        or 0
    )

    total_security_events = (
        db.query(func.count(SecurityEvent.id))
        .scalar()
        or 0
    )

    failed_logins = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.event_type == "LOGIN_FAILED"
        )
        .scalar()
        or 0
    )

    successful_logins = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.event_type == "LOGIN_SUCCESS"
        )
        .scalar()
        or 0
    )

    high_severity_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.severity == "HIGH"
        )
        .scalar()
        or 0
    )

    medium_severity_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.severity == "MEDIUM"
        )
        .scalar()
        or 0
    )

    critical_severity_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.severity == "CRITICAL"
        )
        .scalar()
        or 0
    )

    low_severity_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.severity == "LOW"
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # Rule-based risk analysis
    # --------------------------------------------------------

    user_risk = calculate_user_risk(
        db=db,
        user_id=current_user_id,
    )

    global_risk = calculate_global_risk(
        db=db,
    )

    # --------------------------------------------------------
    # ML threat analysis
    # --------------------------------------------------------

    user_threat = predict_user_threat(
        db=db,
        user_id=current_user_id,
    )

    global_threat = predict_global_threat(
        db=db,
    )

    # --------------------------------------------------------
    # Recent security events
    # --------------------------------------------------------

    recent_events = (
        db.query(SecurityEvent)
        .order_by(
            SecurityEvent.created_at.desc()
        )
        .limit(10)
        .all()
    )

    recent_events_data = [
        {
            "id": event.id,
            "user_id": event.user_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "ip_address": event.ip_address,
            "created_at": event.created_at,
        }
        for event in recent_events
    ]

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "user": {
            "id": (
                user.id
                if user
                else current_user_id
            ),
            "username": (
                user.username
                if user
                else None
            ),
        },

        "statistics": {
            "total_users": total_users,
            "total_messages": total_messages,
            "total_security_events": (
                total_security_events
            ),
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "high_severity_events": (
                high_severity_events
            ),
            "medium_severity_events": (
                medium_severity_events
            ),
            "critical_severity_events": (
                critical_severity_events
            ),
            "low_severity_events": (
                low_severity_events
            ),
        },

        # ----------------------------------------------------
        # Existing rule-based security risk
        # ----------------------------------------------------

        "risk": {
            "user": user_risk,
            "global": global_risk,
        },

        # ----------------------------------------------------
        # New ML threat prediction
        # ----------------------------------------------------

        "ml_threat": {
            "user": user_threat,
            "global": global_threat,
        },

        # ----------------------------------------------------
        # Recent events
        # ----------------------------------------------------

        "recent_events": recent_events_data,
    }


# ============================================================
# CURRENT USER DASHBOARD
# ============================================================

@router.get("")
def get_dashboard(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return the authenticated user's dashboard summary.
    """

    user = (
        db.query(User)
        .filter(User.id == current_user_id)
        .first()
    )

    risk = calculate_user_risk(
        db=db,
        user_id=current_user_id,
    )

    threat = predict_user_threat(
        db=db,
        user_id=current_user_id,
    )

    return {
        "user": {
            "id": current_user_id,
            "username": (
                user.username
                if user
                else None
            ),
        },

        "risk": risk,

        "ml_threat": threat,
    }


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@router.get("/summary")
def get_dashboard_summary(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return compact security statistics for
    the current user.
    """

    risk = calculate_user_risk(
        db=db,
        user_id=current_user_id,
    )

    threat = predict_user_threat(
        db=db,
        user_id=current_user_id,
    )

    return {
        "user_id": current_user_id,

        # Rule-based risk
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "event_count": risk["event_count"],
        "failed_logins": risk["failed_logins"],
        "critical_events": risk["critical_events"],
        "event_summary": risk["event_summary"],
        "window_minutes": risk["window_minutes"],

        # ML prediction
        "ml_threat": threat,
    }


# ============================================================
# GLOBAL SECURITY DASHBOARD
# ============================================================

@router.get("/global")
def get_global_dashboard(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Return global system security statistics
    and ML threat prediction.
    """

    risk = calculate_global_risk(
        db=db,
    )

    threat = predict_global_threat(
        db=db,
    )

    return {
        "risk": risk,
        "ml_threat": threat,
    }