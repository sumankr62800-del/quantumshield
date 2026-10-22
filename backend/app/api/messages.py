
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.security import get_current_user_id
from backend.app.database.connection import get_db
from backend.app.models.message import Message
from backend.app.models.user import User

from backend.app.schemas.message import (
    MessageCreate,
    MessageResponse,
    EncryptedMessageResponse,
)

from backend.app.core.encryption import (
    decrypt_message,
    encrypt_message_pqc,
    decrypt_message_pqc,
)

from backend.app.core.pqc import (
    deserialize_public_key,
    deserialize_private_key,
)


router = APIRouter(
    prefix="/messages",
    tags=["Messages"],
)

logger = logging.getLogger(__name__)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_user_public_key(user):
    """Read the stored PQC public key from the User model."""
    return getattr(user, "pqc_public_key", None)


def get_user_private_key(user):
    """Read the stored encrypted PQC private key."""
    return getattr(user, "pqc_private_key", None)


# ============================================================
# GET ALL USERS
# ============================================================

@router.get("/users")
def get_users(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .filter(User.id != current_user_id)
        .all()
    )

    return [
        {
            "id": user.id,
            "username": user.username,
            "pqc_enabled": bool(
                get_user_public_key(user)
                and get_user_private_key(user)
            ),
        }
        for user in users
    ]


# ============================================================
# SEND POST-QUANTUM ENCRYPTED MESSAGE
# ============================================================

@router.post(
    "/send",
    response_model=EncryptedMessageResponse,
)
def send_message(
    message_data: MessageCreate,
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):

    # Prevent users from sending messages to themselves.
    if message_data.receiver_id == current_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot send a message to yourself.",
        )

    # Retrieve sender.
    sender = (
        db.query(User)
        .filter(User.id == current_user_id)
        .first()
    )

    # Retrieve receiver.
    receiver = (
        db.query(User)
        .filter(User.id == message_data.receiver_id)
        .first()
    )

    if sender is None or receiver is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sender or receiver not found.",
        )

    # Retrieve hexadecimal public keys.
    sender_public_key_data = get_user_public_key(sender)
    receiver_public_key_data = get_user_public_key(receiver)

    # ========================================================
    # PREVENT SILENT PQC DOWNGRADE
    # ========================================================

    if not sender_public_key_data or not receiver_public_key_data:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Post-quantum encryption is unavailable. "
                "Both users must have PQC public keys."
            ),
        )

    try:

        # ====================================================
        # DESERIALIZE ML-KEM-768 PUBLIC KEYS
        # ====================================================

        sender_public_key = deserialize_public_key(
            sender_public_key_data
        )

        receiver_public_key = deserialize_public_key(
            receiver_public_key_data
        )

        # ====================================================
        # ENCRYPT USING ML-KEM-768 + AES-256-GCM
        # ====================================================

        (
            ciphertext,
            nonce,
            sender_kem_ciphertext,
            receiver_kem_ciphertext,
        ) = encrypt_message_pqc(
            message_data.content,
            sender_public_key,
            receiver_public_key,
        )

        # ====================================================
        # STORE ENCRYPTED MESSAGE
        # ====================================================

        message = Message(
            sender_id=current_user_id,
            receiver_id=message_data.receiver_id,
            ciphertext=ciphertext,
            nonce=nonce,
            sender_kem_ciphertext=sender_kem_ciphertext,
            receiver_kem_ciphertext=receiver_kem_ciphertext,
        )

        db.add(message)
        db.commit()
        db.refresh(message)

    except Exception as error:

        db.rollback()

        logger.error(
            "Message encryption or storage failed: %s",
            type(error).__name__,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Message encryption or storage failed.",
        ) from error

    # ========================================================
    # RETURN ENCRYPTED MESSAGE RESPONSE
    # ========================================================

    return EncryptedMessageResponse(
        id=message.id,
        sender_id=message.sender_id,
        receiver_id=message.receiver_id,
        ciphertext=message.ciphertext,
        nonce=message.nonce,
        sender_kem_ciphertext=message.sender_kem_ciphertext,
        receiver_kem_ciphertext=message.receiver_kem_ciphertext,
        created_at=message.created_at,
    )


# ============================================================
# GET MESSAGE HISTORY
# ============================================================

@router.get(
    "/",
    response_model=list[MessageResponse],
)
def get_messages(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):

    # Fetch only messages involving the authenticated user.
    messages = (
        db.query(Message)
        .filter(
            (Message.sender_id == current_user_id)
            | (Message.receiver_id == current_user_id)
        )
        .order_by(Message.created_at.asc())
        .all()
    )

    current_user = (
        db.query(User)
        .filter(User.id == current_user_id)
        .first()
    )

    results = []

    for message in messages:

        try:

            # =================================================
            # DECRYPT PQC-ENCRYPTED MESSAGE
            # =================================================

            if (
                message.sender_kem_ciphertext
                and message.receiver_kem_ciphertext
            ):

                if current_user is None:
                    raise ValueError(
                        "Current user not found."
                    )

                # Select the KEM package belonging to
                # the currently authenticated user.
                if current_user_id == message.sender_id:
                    kem_package = message.sender_kem_ciphertext
                else:
                    kem_package = message.receiver_kem_ciphertext

                # Retrieve encrypted private key.
                private_key_data = get_user_private_key(
                    current_user
                )

                if not private_key_data:
                    raise ValueError(
                        "PQC private key is unavailable."
                    )

                # Deserialize the ML-KEM-768 private key.
                private_key = deserialize_private_key(
                    private_key_data
                )

                # Decrypt the message.
                content = decrypt_message_pqc(
                    message.ciphertext,
                    message.nonce,
                    kem_package,
                    private_key,
                )

            elif (
                message.sender_kem_ciphertext is None
                and message.receiver_kem_ciphertext is None
            ):

                # Legacy AES-GCM-only message.
                content = decrypt_message(
                    message.ciphertext,
                    message.nonce,
                )

            else:

                # A partially populated KEM package is invalid.
                raise ValueError(
                    "Incomplete PQC message metadata."
                )

        except Exception:

            # Do not expose internal cryptographic errors.
            logger.warning(
                "Unable to decrypt message ID %s",
                message.id,
            )

            content = "[Unable to decrypt message]"

        results.append(
            MessageResponse(
                id=message.id,
                sender_id=message.sender_id,
                receiver_id=message.receiver_id,
                content=content,
                created_at=message.created_at,
            )
        )

    return results
