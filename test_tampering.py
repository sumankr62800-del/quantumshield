
from test_api_pqc import (
    unique_user,
    register_user,
    login_user,
    client,
    TestingSessionLocal,
)

from backend.app.models.message import Message


# ============================================================
# TEST: TAMPERED CIPHERTEXT MUST BE REJECTED
# ============================================================

def test_tampered_ciphertext_is_rejected():

    alice = unique_user("alice")
    bob = unique_user("bob")

    register_user(alice)
    bob_data = register_user(bob)

    alice_token = login_user(alice)
    bob_token = login_user(bob)

    alice_headers = {
        "Authorization": f"Bearer {alice_token}"
    }

    bob_headers = {
        "Authorization": f"Bearer {bob_token}"
    }

    plaintext = "Tamper detection test"

    # --------------------------------------------------------
    # Send an encrypted message
    # --------------------------------------------------------

    response = client.post(
        "/messages/send",
        headers=alice_headers,
        json={
            "receiver_id": bob_data["id"],
            "content": plaintext,
        },
    )

    assert response.status_code == 200, response.text

    message_id = response.json()["id"]

    # --------------------------------------------------------
    # Modify the stored ciphertext
    # --------------------------------------------------------

    with TestingSessionLocal() as db:

        message = db.get(Message, message_id)

        assert message is not None

        original_ciphertext = message.ciphertext

        # Decode the hexadecimal ciphertext into bytes.
        ciphertext_bytes = bytearray(
            bytes.fromhex(original_ciphertext)
        )

        assert len(ciphertext_bytes) > 0

        # Flip one bit in the first byte.
        # XOR guarantees that the value changes.
        ciphertext_bytes[0] ^= 0x01

        tampered_ciphertext = ciphertext_bytes.hex()

        assert tampered_ciphertext != original_ciphertext

        message.ciphertext = tampered_ciphertext

        db.commit()

        # Confirm the modified ciphertext was saved.
        db.refresh(message)

        assert message.ciphertext == tampered_ciphertext

    # --------------------------------------------------------
    # Bob attempts to decrypt the tampered message
    # --------------------------------------------------------

    try:
        response = client.get(
            "/messages/",
            headers=bob_headers,
        )

        assert response.status_code == 200, response.text

        messages = response.json()

        target = [
            msg
            for msg in messages
            if msg["id"] == message_id
        ]

        assert len(target) == 1

        assert target[0]["content"] == (
            "[Unable to decrypt message]"
        )

    finally:
        # ----------------------------------------------------
        # Restore the original ciphertext
        # ----------------------------------------------------

        with TestingSessionLocal() as db:

            message = db.get(Message, message_id)

            if message is not None:
                message.ciphertext = original_ciphertext
                db.commit()
