
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.database.connection import Base, get_db
from backend.app.models.user import User


# ============================================================
# ISOLATED TEST DATABASE AND CLIENT
# ============================================================

@pytest.fixture
def client():
    test_engine = create_engine(
        "sqlite://",
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

    # Preserve any existing override.
    previous_override = app.dependency_overrides.get(get_db)

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client, TestingSessionLocal
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override

        test_engine.dispose()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def unique_user(prefix: str):
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"

    return {
        "username": username,
        "email": f"{username}@example.com",
        "password": "TestPassword123!",
    }


def register_user(client, user):
    response = client.post(
        "/auth/register",
        json=user,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["username"] == user["username"]
    assert data["email"] == user["email"]
    assert "id" in data

    return data


def login_user(client, user):
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


def verify_token_identity(
    client,
    TestingSessionLocal,
    token,
    expected_user_id,
):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Verify the token is accepted by a protected endpoint.
    response = client.get(
        "/messages/",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    # Verify the registered user exists in this test database.
    with TestingSessionLocal() as db:
        user = (
            db.query(User)
            .filter(User.id == expected_user_id)
            .first()
        )

        assert user is not None
        assert user.is_active is True


# ============================================================
# TEST 1: PQC API END-TO-END
# ============================================================

def test_pqc_api_end_to_end(client):
    test_client, TestingSessionLocal = client

    alice = unique_user("alice")
    bob = unique_user("bob")

    alice_data = register_user(test_client, alice)
    bob_data = register_user(test_client, bob)

    alice_id = alice_data["id"]
    bob_id = bob_data["id"]

    assert alice_id != bob_id

    alice_token = login_user(test_client, alice)
    bob_token = login_user(test_client, bob)

    verify_token_identity(
        test_client,
        TestingSessionLocal,
        alice_token,
        alice_id,
    )

    verify_token_identity(
        test_client,
        TestingSessionLocal,
        bob_token,
        bob_id,
    )

    alice_headers = {
        "Authorization": f"Bearer {alice_token}"
    }

    bob_headers = {
        "Authorization": f"Bearer {bob_token}"
    }

    plaintext = "QuantumShield API PQC integration test"

    # Alice sends an encrypted message to Bob.
    response = test_client.post(
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

    assert sent_message["ciphertext"] != plaintext
    assert sent_message["sender_kem_ciphertext"]
    assert sent_message["receiver_kem_ciphertext"]

    message_id = sent_message["id"]

    # Bob retrieves and decrypts the message.
    response = test_client.get(
        "/messages/",
        headers=bob_headers,
    )

    assert response.status_code == 200, response.text

    bob_message = next(
        (
            message
            for message in response.json()
            if message["id"] == message_id
        ),
        None,
    )

    assert bob_message is not None
    assert bob_message["content"] == plaintext
    assert bob_message["sender_id"] == alice_id
    assert bob_message["receiver_id"] == bob_id

    # Alice can also retrieve her sent message.
    response = test_client.get(
        "/messages/",
        headers=alice_headers,
    )

    assert response.status_code == 200, response.text

    alice_message = next(
        (
            message
            for message in response.json()
            if message["id"] == message_id
        ),
        None,
    )

    assert alice_message is not None
    assert alice_message["content"] == plaintext


# ============================================================
# TEST 2: UNRELATED USER CANNOT READ PRIVATE MESSAGES
# ============================================================

def test_unrelated_user_cannot_access_other_users_messages(client):
    test_client, _ = client

    alice = unique_user("alice")
    bob = unique_user("bob")
    charlie = unique_user("charlie")

    alice_data = register_user(test_client, alice)
    bob_data = register_user(test_client, bob)
    charlie_data = register_user(test_client, charlie)

    assert len({
        alice_data["id"],
        bob_data["id"],
        charlie_data["id"],
    }) == 3

    alice_token = login_user(test_client, alice)
    bob_token = login_user(test_client, bob)
    charlie_token = login_user(test_client, charlie)

    alice_headers = {
        "Authorization": f"Bearer {alice_token}"
    }

    bob_headers = {
        "Authorization": f"Bearer {bob_token}"
    }

    charlie_headers = {
        "Authorization": f"Bearer {charlie_token}"
    }

    plaintext = "Private Alice-to-Bob isolation test"

    # Alice sends a private message to Bob.
    response = test_client.post(
        "/messages/send",
        headers=alice_headers,
        json={
            "receiver_id": bob_data["id"],
            "content": plaintext,
        },
    )

    assert response.status_code == 200, response.text

    message_id = response.json()["id"]

    # Bob must be able to read the message.
    response = test_client.get(
        "/messages/",
        headers=bob_headers,
    )

    assert response.status_code == 200, response.text

    assert any(
        message["id"] == message_id
        and message["content"] == plaintext
        for message in response.json()
    )

    # Charlie must not see Alice and Bob's message.
    response = test_client.get(
        "/messages/",
        headers=charlie_headers,
    )

    assert response.status_code == 200, response.text

    assert all(
        message["id"] != message_id
        for message in response.json()
    )
