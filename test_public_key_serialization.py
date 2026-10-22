from backend.app.core.pqc import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    encapsulate,
    decapsulate,
)


def test_public_key_serialization():
    private_key, public_key = generate_keypair()

    public_key_data = serialize_public_key(
        public_key
    )

    restored_public_key = deserialize_public_key(
        public_key_data
    )

    assert (
        restored_public_key.public_bytes_raw()
        == public_key.public_bytes_raw()
    )

    shared_secret_1, ciphertext = encapsulate(
        restored_public_key
    )

    shared_secret_2 = decapsulate(
        private_key,
        ciphertext,
    )

    assert shared_secret_1 == shared_secret_2
    assert len(shared_secret_1) == 32