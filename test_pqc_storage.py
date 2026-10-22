from backend.app.core.pqc import (
    generate_keypair,
    serialize_private_key,
    deserialize_private_key,
    encapsulate,
    decapsulate,
)


def test_private_key_storage():
    # Generate original ML-KEM-768 key pair
    private_key, public_key = generate_keypair()

    # Encrypt/serialize private key
    encrypted_private_key = serialize_private_key(
        private_key
    )

    assert encrypted_private_key
    assert isinstance(
        encrypted_private_key,
        str,
    )

    # Restore private key
    restored_private_key = deserialize_private_key(
        encrypted_private_key
    )

    assert restored_private_key is not None

    # Verify restored key actually works
    shared_secret_1, ciphertext = encapsulate(
        public_key
    )

    shared_secret_2 = decapsulate(
        restored_private_key,
        ciphertext,
    )

    assert shared_secret_1 == shared_secret_2