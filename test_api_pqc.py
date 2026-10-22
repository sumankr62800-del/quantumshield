
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.database.connection import Base, get_db


TEST_DATABASE_URL = "sqlite://"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)

Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


def unique_user(prefix: str):
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    return {
        "username": username,
        "email": f"{username}@example.com",
        "password": "TestPassword123!",
    }


def register_user(user):
    response = client.post("/auth/register", json=user)
    assert response.status_code == 200, response.text

    data = response.json()
    assert data["username"] == user["username"]
    assert data["email"] == user["email"]
    assert "id" in data

    return data


def login_user(user):
    response = client.post(
        "/auth/login",
        data={
            "username": user["username"],
            "password": user["password"],
        },
    )
    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    return data["access_token"]


def test_pqc_api_end_to_end():
    alice = unique_user("alice")
    bob = unique_user("bob")

    alice_data = register_user(alice)
    bob_data = register_user(bob)

    alice_id = alice_data["id"]
    bob_id = bob_data["id"]

    assert alice_id != bob_id

    alice_token = login_user(alice)
    bob_token = login_user(bob)

    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    # Verify that both tokens authenticate against a protected endpoint.
    response = client.get("/messages/", headers=alice_headers)
    assert response.status_code == 200, response.text

    response = client.get("/messages/", headers=bob_headers)
    assert response.status_code == 200, response.text

    plaintext = "QuantumShield API PQC integration test"

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
    assert "nonce" in sent_message
    assert "content" not in sent_message

    message_id = sent_message["id"]

    # Bob retrieves and decrypts the message.
    response = client.get("/messages/", headers=bob_headers)
    assert response.status_code == 200, response.text

    matching_messages = [
        message
        for message in response.json()
        if message["id"] == message_id
    ]

    assert len(matching_messages) == 1

    received_message = matching_messages[0]
    assert received_message["content"] == plaintext
    assert received_message["sender_id"] == alice_id
    assert received_message["receiver_id"] == bob_id

    # Alice can also retrieve her sent message.
    response = client.get("/messages/", headers=alice_headers)
    assert response.status_code == 200, response.text

    alice_messages = response.json()
    sent_copy = next(
        (message for message in alice_messages
         if message["id"] == message_id),
        None,
    )

    assert sent_copy is not None
    assert sent_copy["content"] == plaintext


def test_unrelated_user_cannot_access_other_users_messages():
    alice = unique_user("alice")
    bob = unique_user("bob")
    charlie = unique_user("charlie")

    alice_data = register_user(alice)
    bob_data = register_user(bob)
    register_user(charlie)

    alice_token = login_user(alice)
    bob_token = login_user(bob)
    charlie_token = login_user(charlie)

    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    charlie_headers = {"Authorization": f"Bearer {charlie_token}"}

    plaintext = "Private Alice-to-Bob isolation test"

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

    # Bob must be able to retrieve the message.
    response = client.get("/messages/", headers=bob_headers)
    assert response.status_code == 200, response.text

    assert any(
        message["id"] == message_id
        and message["content"] == plaintext
        for message in response.json()
    )

    # Charlie must not see Alice and Bob's message.
    response = client.get("/messages/", headers=charlie_headers)
    assert response.status_code == 200, response.text

    assert all(
        message["id"] != message_id
        for message in response.json()
    )
