
from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.schemas.user import UserCreate

from backend.app.core.security import (
    hash_password,
    verify_password,
)

from backend.app.core.pqc import (
    generate_keypair,
    serialize_public_key,
    serialize_private_key,
)


# ============================================================
# CREATE USER
# ============================================================

def create_user(
    db: Session,
    user_data: UserCreate,
) -> User:

    # --------------------------------------------------------
    # Check whether username already exists
    # --------------------------------------------------------

    existing_username = (
        db.query(User)
        .filter(User.username == user_data.username)
        .first()
    )

    if existing_username:
        raise ValueError("Username already exists")

    # --------------------------------------------------------
    # Check whether email already exists
    # --------------------------------------------------------

    existing_email = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_email:
        raise ValueError("Email already exists")

    # --------------------------------------------------------
    # Generate ML-KEM-768 key pair
    # --------------------------------------------------------

    private_key, public_key = generate_keypair()

    # --------------------------------------------------------
    # Serialize public key
    # --------------------------------------------------------

    public_key_data = serialize_public_key(
        public_key
    )

    # --------------------------------------------------------
    # Encrypt and serialize private key
    # --------------------------------------------------------

    private_key_data = serialize_private_key(
        private_key
    )

    # --------------------------------------------------------
    # Create database user
    # --------------------------------------------------------

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(
            user_data.password
        ),
        is_active=True,
        pqc_public_key=public_key_data,
        pqc_private_key=private_key_data,
    )

    # --------------------------------------------------------
    # Save user and encrypted keys
    # --------------------------------------------------------

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ============================================================
# AUTHENTICATE USER
# ============================================================

def authenticate_user(
    db: Session,
    username: str,
    password: str,
):
    """
    Authenticate a user.

    Returns:
        (user, True):
            Username exists and password is correct.

        (user, False):
            Username exists but password is incorrect.

        (None, False):
            Username does not exist.

    Returning the user on an incorrect password allows
    the security layer to associate failed login attempts
    with the correct account.
    """

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    # --------------------------------------------------------
    # Username does not exist
    # --------------------------------------------------------

    if not user:
        return None, False

    # --------------------------------------------------------
    # Verify password
    # --------------------------------------------------------

    if not verify_password(
        password,
        user.hashed_password,
    ):
        return user, False

    # --------------------------------------------------------
    # Authentication successful
    # --------------------------------------------------------

    return user, True
