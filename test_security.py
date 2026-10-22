
from test_api_pqc import (
    unique_user,
    register_user,
    login_user,
    client,
)


def test_invalid_token_rejected():
    response = client.get(
        "/messages/",
        headers={
            "Authorization": "Bearer completely-invalid-token"
        },
    )

    assert response.status_code == 401


def test_missing_token_rejected():
    response = client.get("/messages/")

    assert response.status_code == 401


def test_nonexistent_receiver_rejected():
    alice = unique_user("alice")

    register_user(alice)
    token = login_user(alice)

    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/messages/send",
        headers=headers,
        json={
            "receiver_id": 999999999,
            "content": "This should not be sent",
        },
    )

    assert response.status_code == 404, response.text
