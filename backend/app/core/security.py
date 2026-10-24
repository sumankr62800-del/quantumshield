
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.database.connection import get_db
from backend.app.models.user import User


# ============================================================
# PASSWORD SECURITY
# ============================================================

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password
    )


# ============================================================
# JWT TOKEN GENERATION
# ============================================================

def create_access_token(
    username: str,
    expires_minutes: int | None = None
) -> str:

    if expires_minutes is None:
        expires_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes
    )

    payload = {
        "sub": username,
        "exp": expire
    }

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


# ============================================================
# JWT TOKEN VERIFICATION
# ============================================================

def verify_access_token(token: str) -> str | None:

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        username = payload.get("sub")

        if not isinstance(username, str) or not username:
            return None

        return username

    except jwt.InvalidTokenError:
        return None


# ============================================================
# GET CURRENT AUTHENTICATED USER
# ============================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:

    username = verify_access_token(token)

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    return user


# ============================================================
# GET CURRENT USER ID
# Backward compatible with existing QuantumShield routes
# ============================================================

def get_current_user_id(
    current_user: User = Depends(get_current_user)
) -> int:

    return current_user.id


# ============================================================
# ADMIN AUTHORIZATION
# ============================================================

def require_admin(
    current_user: User = Depends(get_current_user)
) -> User:

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required"
        )

    return current_user
