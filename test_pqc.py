from backend.app.core.pqc import (
    generate_keypair,
    encapsulate,
    decapsulate,
)


def test_mlkem768_exchange():
    bob_private, bob_public = generate_keypair()

    alice_secret, ciphertext = encapsulate(
        bob_public
    )

    bob_secret = decapsulate(
        bob_private,
        ciphertext,
    )

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32
    assert len(ciphertext) > 0