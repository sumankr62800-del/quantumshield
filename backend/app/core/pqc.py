
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core.config import settings


# ============================================================
# ENCRYPTION KEY CONFIGURATION
# ============================================================

try:
    KEY = bytes.fromhex(settings.MESSAGE_ENCRYPTION_KEY)
except ValueError as exc:
    raise RuntimeError(
        "MESSAGE_ENCRYPTION_KEY must be valid hexadecimal."
    ) from exc

if len(KEY) != 32:
    raise RuntimeError(
        "MESSAGE_ENCRYPTION_KEY must contain exactly 32 bytes."
    )


# ============================================================
# ML-KEM-768 KEY GENERATION
# ============================================================

def generate_keypair():
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# ML-KEM-768 ENCAPSULATION
# ============================================================

def encapsulate(public_key):
    shared_secret, ciphertext = public_key.encapsulate()

    return shared_secret, ciphertext


# ============================================================
# ML-KEM-768 DECAPSULATION
# ============================================================

def decapsulate(private_key, ciphertext):
    return private_key.decapsulate(ciphertext)


# ============================================================
# PUBLIC KEY SERIALIZATION
# ============================================================

def serialize_public_key(public_key) -> str:
    return public_key.public_bytes_raw().hex()


def deserialize_public_key(data: str):
    return mlkem.MLKEM768PublicKey.from_public_bytes(
        bytes.fromhex(data)
    )


# ============================================================
# PRIVATE KEY ENCRYPTION
# ============================================================

def serialize_private_key(private_key) -> str:
    """
    Encrypt an ML-KEM-768 private-key seed using AES-256-GCM.

    Storage format:
        12-byte nonce + encrypted seed + 16-byte GCM tag

    The output is hexadecimal encoded.

    This preserves compatibility with existing stored keys.
    """

    seed = private_key.private_bytes_raw()

    nonce = os.urandom(12)

    encrypted_seed = AESGCM(KEY).encrypt(
        nonce,
        seed,
        None,
    )

    return (nonce + encrypted_seed).hex()


# ============================================================
# PRIVATE KEY DECRYPTION
# ============================================================

def deserialize_private_key(data: str):
    """
    Decrypt a stored ML-KEM-768 private-key seed.

    Reject malformed data, incorrect encryption keys,
    and modified encrypted private-key material.
    """

    if not isinstance(data, str) or not data:
        raise ValueError(
            "Encrypted private-key data is missing."
        )

    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        raise ValueError(
            "Encrypted private-key data is malformed."
        ) from exc

    # At minimum: 12-byte nonce + 16-byte authentication tag.
    if len(raw) < 28:
        raise ValueError(
            "Encrypted private-key data is too short."
        )

    nonce = raw[:12]
    encrypted_seed = raw[12:]

    try:
        seed = AESGCM(KEY).decrypt(
            nonce,
            encrypted_seed,
            None,
        )
    except InvalidTag as exc:
        raise ValueError(
            "Private-key decryption failed: "
            "invalid key or corrupted data."
        ) from exc

    try:
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(
            seed
        )
    except ValueError as exc:
        raise ValueError(
            "Decrypted ML-KEM-768 seed is invalid."
        ) from exc
