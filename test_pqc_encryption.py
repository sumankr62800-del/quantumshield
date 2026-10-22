from backend.app.core.pqc import (
    generate_keypair,
    encapsulate,
    decapsulate,
)

from backend.app.core.encryption import (
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)


def test_pqc_aes_encryption():
    bob_private, bob_public = generate_keypair()

    alice_secret, ciphertext = encapsulate(
        bob_public
    )

    bob_secret = decapsulate(
        bob_private,
        ciphertext,
    )

    assert alice_secret == bob_secret

    alice_aes_key = derive_aes_key(
        alice_secret
    )

    bob_aes_key = derive_aes_key(
        bob_secret
    )

    assert alice_aes_key == bob_aes_key
    assert len(alice_aes_key) == 32

    encrypted, nonce = encrypt_message(
        "QuantumShield PQC test",
        alice_aes_key,
    )

    decrypted = decrypt_message(
        encrypted,
        nonce,
        bob_aes_key,
    )

    assert decrypted == "QuantumShield PQC test"