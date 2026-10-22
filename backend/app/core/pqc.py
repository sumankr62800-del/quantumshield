import os

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core.config import settings


# ============================================================
# ML-KEM-768 KEY GENERATION
# ============================================================

def generate_keypair():
    """
    Generate an ML-KEM-768 public/private key pair.
    """

    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# ML-KEM-768 ENCAPSULATION
# ============================================================

def encapsulate(public_key):
    """
    Encapsulate a shared secret using the recipient's
    ML-KEM-768 public key.

    Returns:
        shared_secret
        ciphertext
    """

    shared_secret, ciphertext = public_key.encapsulate()

    return shared_secret, ciphertext


# ============================================================
# ML-KEM-768 DECAPSULATION
# ============================================================

def decapsulate(
    private_key,
    ciphertext,
):
    """
    Recover the shared secret using the recipient's
    ML-KEM-768 private key.
    """

    return private_key.decapsulate(
        ciphertext
    )


# ============================================================
# PUBLIC KEY SERIALIZATION
# ============================================================

def serialize_public_key(public_key) -> str:
    """
    Convert ML-KEM-768 public key to hexadecimal string.
    """

    return public_key.public_bytes_raw().hex()


def deserialize_public_key(data: str):
    """
    Convert hexadecimal public-key data back into
    an ML-KEM-768 public-key object.
    """

    return mlkem.MLKEM768PublicKey.from_public_bytes(
        bytes.fromhex(data)
    )


# ============================================================
# PRIVATE KEY ENCRYPTION
# ============================================================

KEY = bytes.fromhex(
    settings.MESSAGE_ENCRYPTION_KEY
)


if len(KEY) != 32:
    raise RuntimeError(
        "MESSAGE_ENCRYPTION_KEY must contain exactly 32 bytes"
    )


def serialize_private_key(
    private_key,
) -> str:
    """
    Encrypt the ML-KEM-768 private-key seed and return
    it as a hexadecimal string for database storage.

    The database never receives the private key in plaintext.
    """

    # Get the raw ML-KEM private-key seed
    seed = private_key.private_bytes_raw()

    # AES-GCM requires a unique nonce
    nonce = os.urandom(12)

    aesgcm = AESGCM(KEY)

    # Encrypt the seed
    encrypted_seed = aesgcm.encrypt(
        nonce,
        seed,
        None,
    )

    # Store nonce + encrypted seed together
    return (
        nonce + encrypted_seed
    ).hex()


# ============================================================
# PRIVATE KEY DECRYPTION
# ============================================================

def deserialize_private_key(
    data: str,
):
    """
    Decrypt the stored ML-KEM-768 private-key seed and
    reconstruct the private-key object.
    """

    # Convert database hexadecimal string back to bytes
    raw = bytes.fromhex(data)

    # First 12 bytes are the AES-GCM nonce
    nonce = raw[:12]

    # Remaining bytes are encrypted private-key seed
    encrypted_seed = raw[12:]

    aesgcm = AESGCM(KEY)

    # Decrypt the seed
    seed = aesgcm.decrypt(
        nonce,
        encrypted_seed,
        None,
    )

    # Reconstruct ML-KEM-768 private key
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(
        seed
    )