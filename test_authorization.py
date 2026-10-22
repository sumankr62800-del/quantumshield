
from test_api_pqc import (
    unique_user,
    register_user,
    login_user,
    client,
)


def test_message_isolation_between_users():
    alice = unique_user("alice")
    bob = unique_user("bob")
    charlie = unique_user("charlie")

    alice_data = register_user(alice)
    bob_data = register_user(bob)
    charlie_data = register_user(charlie)

    alice_id = alice_data["id"]
    bob_id = bob_data["id"]
    charlie_id = charlie_data["id"]

    assert len({alice_id, bob_id, charlie_id}) == 3

    alice_token = login_user(alice)
    charlie_token = login_user(charlie)

    alice_headers = {
        "Authorization": f"Bearer {alice_token}"
    }
    charlie_headers = {
        "Authorization": f"Bearer {charlie_token}"
    }

    plaintext = "Alice to Bob - private message"

    # Send the message. The response contains ciphertext, not plaintext.
    response = client.post(
        "/messages/send",
        headers=alice_headers,
        json={
            "receiver_id": bob_id,
            "content": plaintext,
        },
    )

    assert response.status_code == 200, response.text

    sent_message = response.json()
    assert sent_message["sender_id"] == alice_id
    assert sent_message["receiver_id"] == bob_id
    assert "ciphertext" in sent_message
    assert "content" not in sent_message

    message_id = sent_message["id"]

    # Charlie retrieves only messages belonging to Charlie.
    response = client.get(
        "/messages/",
        headers=charlie_headers,
    )

    assert response.status_code == 200, response.text

    charlie_messages = response.json()

    assert all(
        message["id"] != message_id
        for message in charlie_messages
    )

    assert all(
        message["content"] != plaintext
        for message in charlie_messages
    )
