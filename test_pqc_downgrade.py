
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.database.connection import Base, get_db
from backend.app.models.user import User
from backend.app.models.message import Message


# ============================================================
# ISOLATED TEST DATABASE
# ============================================================

@pytest.fixture
def test_environment():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    previous_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client, TestingSessionLocal
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override

        engine.dispose()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def create_user(client, prefix):
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"

    user_data = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "TestPassword123!",
    }

    response = client.post(
        "/auth/register",
        json=user_data,
    )

    assert response.status_code == 200, response.text

    return user_data, response.json()["id"]


def login_user(client, user_data):
    response = client.post(
        "/auth/login",
        data={
            "username": user_data["username"],
            "password": user_data["password"],
        },
    )

    assert response.status_code == 200, response.text

    return {
        "Authorization": (
            f"Bearer {response.json()['access_token']}"
        )
    }


def send_message(client, headers, receiver_id):
    return client.post(
        "/messages/send",
        headers=headers,
        json={
            "receiver_id": receiver_id,
            "content": "QuantumShield security regression test",
        },
    )


# ============================================================
# TEST 1: MISSING SENDER PQC PUBLIC KEY
# ============================================================

def test_missing_sender_pqc_key_rejected(test_environment):
    client, SessionLocal = test_environment

    alice, alice_id = create_user(client, "alice")
    bob, bob_id = create_user(client, "bob")

    alice_headers = login_user(client, alice)

    # Remove Alice's PQC public key.
    with SessionLocal() as db:
        user = db.get(User, alice_id)
        assert user is not None

        user.pqc_public_key = None
        db.commit()

    response = send_message(
        client,
        alice_headers,
        bob_id,
    )

    assert response.status_code == 409, response.text
    assert "Post-quantum encryption is unavailable" in (
        response.json()["detail"]
    )

    # Confirm that no message was stored.
    with SessionLocal() as db:
        assert db.query(Message).count() == 0


# ============================================================
# TEST 2: MISSING RECEIVER PQC PUBLIC KEY
# ============================================================

def test_missing_receiver_pqc_key_rejected(test_environment):
    client, SessionLocal = test_environment

    alice, alice_id = create_user(client, "alice")
    bob, bob_id = create_user(client, "bob")

    alice_headers = login_user(client, alice)

    # Remove Bob's PQC public key.
    with SessionLocal() as db:
        user = db.get(User, bob_id)
        assert user is not None

        user.pqc_public_key = None
        db.commit()

    response = send_message(
        client,
        alice_headers,
        bob_id,
    )

    assert response.status_code == 409, response.text
    assert "Post-quantum encryption is unavailable" in (
        response.json()["detail"]
    )

    # Confirm that no message was stored.
    with SessionLocal() as db:
        assert db.query(Message).count() == 0


# ============================================================
# TEST 3: INCOMPLETE KEM METADATA
# ============================================================

def test_incomplete_kem_metadata_rejected(test_environment):
    client, SessionLocal = test_environment

    alice, alice_id = create_user(client, "alice")
    bob, bob_id = create_user(client, "bob")

    alice_headers = login_user(client, alice)
    bob_headers = login_user(client, bob)

    # First send a valid PQC-encrypted message.
    response = send_message(
        client,
        alice_headers,
        bob_id,
    )

    assert response.status_code == 200, response.text

    message_id = response.json()["id"]

    # Simulate corruption of the receiver's KEM package.
    with SessionLocal() as db:
        message = db.get(Message, message_id)
        assert message is not None

        assert message.sender_kem_ciphertext is not None
        assert message.receiver_kem_ciphertext is not None

        message.receiver_kem_ciphertext = None
        db.commit()

    # Bob must not receive the plaintext.
    response = client.get(
        "/messages/",
        headers=bob_headers,
    )

    assert response.status_code == 200, response.text

    matching_message = next(
        (
            message
            for message in response.json()
            if message["id"] == message_id
        ),
        None,
    )

    assert matching_message is not None
    assert matching_message["content"] == (
        "[Unable to decrypt message]"
    )
