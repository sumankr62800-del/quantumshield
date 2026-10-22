from typing import Dict

from cryptography.hazmat.primitives.asymmetric import mlkem


_private_keys: Dict[int, mlkem.MLKEM768PrivateKey] = {}


def store_private_key(
    user_id: int,
    private_key: mlkem.MLKEM768PrivateKey,
) -> None:
    _private_keys[user_id] = private_key


def get_private_key(
    user_id: int,
):
    return _private_keys.get(user_id)


def delete_private_key(
    user_id: int,
) -> None:
    _private_keys.pop(user_id, None)