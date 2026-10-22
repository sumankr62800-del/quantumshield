from test_api_pqc import (
    client,
    unique_user,
    register_user,
    login_user,
    TestingSessionLocal,
)

from test_api_pqc import TestingSessionLocal
from backend.app.models.message import Message


def test_tampered_kem_ciphertext_is_rejected():

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

    plaintext = "KEM tamper detection test"

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
    original_kem = None

    try:
        message = (
            db.query(Message)
            .filter(Message.id == message_id)
            .first()
        )

        assert message is not None
        assert message.receiver_kem_ciphertext

        original_kem = message.receiver_kem_ciphertext

        # Tamper with the recipient's ML-KEM ciphertext
        message.receiver_kem_ciphertext = (
            "00" + original_kem[2:]
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

        if message is not None and original_kem is not None:
            message.receiver_kem_ciphertext = original_kem
            db.commit()

        db.close()