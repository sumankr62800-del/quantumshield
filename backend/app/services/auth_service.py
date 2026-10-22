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

from backend.app.core.key_store import store_private_key


def create_user(
    db: Session,
    user_data: UserCreate,
) -> User:

    existing_username = (
        db.query(User)
        .filter(
            User.username == user_data.username
        )
        .first()
    )

    if existing_username:
        raise ValueError(
            "Username already exists"
        )

    existing_email = (
        db.query(User)
        .filter(
            User.email == user_data.email
        )
        .first()
    )

    if existing_email:
        raise ValueError(
            "Email already exists"
        )

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
    # Serialize private key
    # --------------------------------------------------------

    private_key_data = serialize_private_key(
        private_key
    )

    # --------------------------------------------------------
    # Create user
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

    db.add(user)
    db.commit()
    db.refresh(user)

    # --------------------------------------------------------
    # Keep private key available during current process
    # --------------------------------------------------------

    store_private_key(
        user.id,
        private_key,
    )

    return user


def authenticate_user(
    db: Session,
    username: str,
    password: str,
):
    """
    Authenticate a user.

    Returns:
        (user, True)  -> username exists and password is correct
        (user, False) -> username exists but password is wrong
        (None, False) -> username does not exist

    Returning the user on a wrong password allows the security
    layer to associate failed login attempts with the correct
    account without treating the authentication as successful.
    """

    user = (
        db.query(User)
        .filter(
            User.username == username
        )
        .first()
    )

    # Username does not exist
    if not user:
        return None, False

    # Username exists but password is incorrect
    if not verify_password(
        password,
        user.hashed_password,
    ):
        return user, False

    # Authentication successful
    return user, True