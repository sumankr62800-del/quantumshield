import pytest

from backend.app.core.pqc import (
    generate_keypair,
    encapsulate,
)

from backend.app.core.encryption import (
    derive_aes_key,
    encrypt_message,
    decrypt_message_pqc,
)


def test_wrong_private_key_is_rejected():
    # User A key pair
    user_a_private, user_a_public = generate_keypair()

    # User B key pair
    user_b_private, user_b_public = generate_keypair()

    # Encrypt a message for User B
    shared_secret, kem_ciphertext = encapsulate(
        user_b_public
    )

    aes_key = derive_aes_key(
        shared_secret
    )

    ciphertext, nonce = encrypt_message(
        "Secret QuantumShield message",
        aes_key,
    )

    # User A attempts to decrypt User B's message
    with pytest.raises(Exception):
        decrypt_message_pqc(
            ciphertext,
            nonce,
            kem_ciphertext.hex(),
            user_a_private,
        )