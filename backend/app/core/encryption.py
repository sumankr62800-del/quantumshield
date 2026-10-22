import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from backend.app.core.config import settings


# ============================================================
# APPLICATION KEY
# ============================================================

KEY = bytes.fromhex(
    settings.MESSAGE_ENCRYPTION_KEY
)

if len(KEY) != 32:
    raise RuntimeError(
        "MESSAGE_ENCRYPTION_KEY must contain exactly 32 bytes"
    )


# ============================================================
# AES KEY DERIVATION
# ============================================================

def derive_aes_key(
    shared_secret: bytes,
) -> bytes:
    """
    Derive a 32-byte AES-256 key from
    an ML-KEM shared secret.
    """

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuantumShield-AES-256-GCM",
    ).derive(shared_secret)


# ============================================================
# GENERIC AES-GCM ENCRYPTION
# ============================================================

def encrypt_message(
    message: str,
    key: bytes | None = None,
) -> tuple[str, str]:

    encryption_key = key or KEY

    if len(encryption_key) != 32:
        raise ValueError(
            "Encryption key must be exactly 32 bytes"
        )

    nonce = os.urandom(12)

    aesgcm = AESGCM(
        encryption_key
    )

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode("utf-8"),
        None,
    )

    return (
        ciphertext.hex(),
        nonce.hex(),
    )


# ============================================================
# GENERIC AES-GCM DECRYPTION
# ============================================================

def decrypt_message(
    ciphertext: str,
    nonce: str,
    key: bytes | None = None,
) -> str:

    encryption_key = key or KEY

    if len(encryption_key) != 32:
        raise ValueError(
            "Encryption key must be exactly 32 bytes"
        )

    aesgcm = AESGCM(
        encryption_key
    )

    plaintext = aesgcm.decrypt(
        bytes.fromhex(nonce),
        bytes.fromhex(ciphertext),
        None,
    )

    return plaintext.decode(
        "utf-8"
    )


# ============================================================
# PQC MESSAGE ENCRYPTION
# ============================================================

def encrypt_message_pqc(
    message: str,
    sender_public_key,
    receiver_public_key,
) -> tuple[str, str, str, str]:
    """
    Encrypt one message using a random AES-256 key.

    The AES key is separately wrapped using ML-KEM-768
    for both the sender and receiver.

    Returns:

        ciphertext
        nonce
        sender_kem_ciphertext
        receiver_kem_ciphertext
    """

    # --------------------------------------------------------
    # Generate a random AES-256 message key
    # --------------------------------------------------------

    message_key = os.urandom(32)

    # --------------------------------------------------------
    # Encrypt actual message using AES-256-GCM
    # --------------------------------------------------------

    ciphertext, nonce = encrypt_message(
        message,
        key=message_key,
    )

    # --------------------------------------------------------
    # Encapsulate for sender
    # --------------------------------------------------------

    sender_shared_secret, sender_kem_ciphertext = (
        sender_public_key.encapsulate()
    )

    sender_aes_key = derive_aes_key(
        sender_shared_secret
    )

    # Encrypt the message key using the sender-derived key
    encrypted_message_key_sender, sender_key_nonce = (
        encrypt_message(
            message_key.hex(),
            key=sender_aes_key,
        )
    )

    # --------------------------------------------------------
    # Encapsulate for receiver
    # --------------------------------------------------------

    receiver_shared_secret, receiver_kem_ciphertext = (
        receiver_public_key.encapsulate()
    )

    receiver_aes_key = derive_aes_key(
        receiver_shared_secret
    )

    # Encrypt the message key using receiver-derived key
    encrypted_message_key_receiver, receiver_key_nonce = (
        encrypt_message(
            message_key.hex(),
            key=receiver_aes_key,
        )
    )

    # --------------------------------------------------------
    # Store the encrypted message keys together with the
    # corresponding KEM ciphertext and nonce.
    #
    # Format:
    #
    # sender_kem_ciphertext:
    #   kem_ciphertext : nonce : encrypted_message_key
    #
    # receiver_kem_ciphertext:
    #   kem_ciphertext : nonce : encrypted_message_key
    # --------------------------------------------------------

    sender_package = (
        sender_kem_ciphertext.hex()
        + ":"
        + sender_key_nonce
        + ":"
        + encrypted_message_key_sender
    )

    receiver_package = (
        receiver_kem_ciphertext.hex()
        + ":"
        + receiver_key_nonce
        + ":"
        + encrypted_message_key_receiver
    )

    return (
        ciphertext,
        nonce,
        sender_package,
        receiver_package,
    )


# ============================================================
# PQC MESSAGE DECRYPTION
# ============================================================

def decrypt_message_pqc(
    ciphertext: str,
    nonce: str,
    kem_package: str,
    private_key,
) -> str:
    """
    Decrypt a PQC message using the supplied user's
    ML-KEM-768 private key.
    """

    # --------------------------------------------------------
    # Split KEM package
    # --------------------------------------------------------

    parts = kem_package.split(":")

    if len(parts) != 3:
        raise ValueError(
            "Invalid PQC KEM package"
        )

    kem_ciphertext_hex = parts[0]
    key_nonce = parts[1]
    encrypted_message_key = parts[2]

    # --------------------------------------------------------
    # ML-KEM decapsulation
    # --------------------------------------------------------

    shared_secret = private_key.decapsulate(
        bytes.fromhex(
            kem_ciphertext_hex
        )
    )

    # --------------------------------------------------------
    # Derive AES key
    # --------------------------------------------------------

    wrapping_key = derive_aes_key(
        shared_secret
    )

    # --------------------------------------------------------
    # Recover original AES message key
    # --------------------------------------------------------

    message_key_hex = decrypt_message(
        encrypted_message_key,
        key_nonce,
        key=wrapping_key,
    )

    message_key = bytes.fromhex(
        message_key_hex
    )

    if len(message_key) != 32:
        raise ValueError(
            "Invalid recovered message key"
        )

    # --------------------------------------------------------
    # Decrypt actual message
    # --------------------------------------------------------

    return decrypt_message(
        ciphertext,
        nonce,
        key=message_key,
    )