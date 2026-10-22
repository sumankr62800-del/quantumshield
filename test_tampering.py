from test_api_pqc import (
    unique_user,
    register_user,
    login_user,
    client,
)

from test_api_pqc import TestingSessionLocal
from backend.app.models.message import Message


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

    response = client.post(
        "/messages/send",
        headers=alice_headers,
        json={
            "receiver_id": bob_data["id"],
            "content": plaintext,
        },
    )

    assert response.status_code == 200

    message_id = response.json()["id"]

    db = TestingSessionLocal()

    original_ciphertext = None

    try:
        message = (
            db.query(Message)
            .filter(Message.id == message_id)
            .first()
        )

        assert message is not None

        original_ciphertext = message.ciphertext

        # Tamper with ciphertext
        message.ciphertext = (
            "00" + original_ciphertext[2:]
        )

        db.commit()

        # Bob attempts to decrypt
        response = client.get(
            "/messages/",
            headers=bob_headers,
        )

        assert response.status_code == 200

        messages = response.json()

        target = [
            msg
            for msg in messages
            if msg["id"] == message_id
        ]

        assert len(target) == 1

        assert (
            target[0]["content"]
            == "[Unable to decrypt message]"
        )

    finally:
        # Restore database state
        message = (
            db.query(Message)
            .filter(Message.id == message_id)
            .first()
        )

        if message is not None and original_ciphertext is not None:
            message.ciphertext = original_ciphertext
            db.commit()

        db.close()