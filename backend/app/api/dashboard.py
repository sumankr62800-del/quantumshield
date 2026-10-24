
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.core.security import (
    get_current_user,
    require_admin,
)

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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Personal dashboard for regular users.

    Administrators also receive global security statistics.
    """

    user_id = current_user.id
    is_admin = current_user.role == "admin"

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    if is_admin:
        total_users = (
            db.query(func.count(User.id)).scalar() or 0
        )

        total_messages = (
            db.query(func.count(Message.id)).scalar() or 0
        )

        event_query = db.query(SecurityEvent)

    else:
        # Do not expose global user counts.
        total_users = 1

        # Count messages involving this user only.
        total_messages = (
            db.query(func.count(Message.id))
            .filter(
                (Message.sender_id == user_id)
                | (Message.receiver_id == user_id)
            )
            .scalar()
            or 0
        )

        event_query = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.user_id == user_id)
        )

    events = event_query.all()

    total_security_events = len(events)

    def count_events(event_type=None, severity=None):
        return sum(
            1
            for event in events
            if (
                event_type is None
                or event.event_type == event_type
            )
            and (
                severity is None
                or event.severity == severity
            )
        )

    statistics = {
        "total_users": total_users,
        "total_messages": total_messages,
        "total_security_events": total_security_events,
        "failed_logins": count_events(
            event_type="LOGIN_FAILED"
        ),
        "successful_logins": count_events(
            event_type="LOGIN_SUCCESS"
        ),
        "high_severity_events": count_events(
            severity="HIGH"
        ),
        "medium_severity_events": count_events(
            severity="MEDIUM"
        ),
        "critical_severity_events": count_events(
            severity="CRITICAL"
        ),
        "low_severity_events": count_events(
            severity="LOW"
        ),
    }

    # --------------------------------------------------------
    # Personal risk and ML prediction
    # --------------------------------------------------------

    user_risk = calculate_user_risk(
        db=db,
        user_id=user_id,
    )

    user_threat = predict_user_threat(
        db=db,
        user_id=user_id,
    )

    # --------------------------------------------------------
    # Global risk and ML prediction (admin only)
    # --------------------------------------------------------

    global_risk = None
    global_threat = None

    if is_admin:
        global_risk = calculate_global_risk(db=db)
        global_threat = predict_global_threat(db=db)

    # --------------------------------------------------------
    # Recent security events
    # --------------------------------------------------------

    recent_events = (
        event_query
        .order_by(SecurityEvent.created_at.desc())
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
            "ip_address": (
                event.ip_address if is_admin else None
            ),
            "created_at": event.created_at,
        }
        for event in recent_events
    ]

    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
        },

        "statistics": statistics,

        "risk": {
            "user": user_risk,
            "global": global_risk,
        },

        "ml_threat": {
            "user": user_threat,
            "global": global_threat,
        },

        "recent_events": recent_events_data,
    }


# ============================================================
# CURRENT USER DASHBOARD
# ============================================================

@router.get("")
def get_dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    risk = calculate_user_risk(
        db=db,
        user_id=current_user.id,
    )

    threat = predict_user_threat(
        db=db,
        user_id=current_user.id,
    )

    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
        },
        "risk": risk,
        "ml_threat": threat,
    }


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@router.get("/summary")
def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    risk = calculate_user_risk(
        db=db,
        user_id=current_user.id,
    )

    threat = predict_user_threat(
        db=db,
        user_id=current_user.id,
    )

    return {
        "user_id": current_user.id,
        "role": current_user.role,

        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "event_count": risk["event_count"],
        "failed_logins": risk["failed_logins"],
        "critical_events": risk["critical_events"],
        "event_summary": risk["event_summary"],
        "window_minutes": risk["window_minutes"],

        "ml_threat": threat,
    }


# ============================================================
# GLOBAL SECURITY DASHBOARD — ADMIN ONLY
# ============================================================

@router.get("/global")
def get_global_dashboard(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Only administrators can access global security data.
    """

    risk = calculate_global_risk(db=db)
    threat = predict_global_threat(db=db)

    return {
        "risk": risk,
        "ml_threat": threat,
    }
