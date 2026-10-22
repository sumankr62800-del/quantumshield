
from backend.app.core.encryption import (
    encrypt_message,
    decrypt_message,
)


def test_aes_gcm_encrypt_decrypt():
    """The original message must be recovered after encryption."""
    original_message = "QuantumShield security test 123"

    ciphertext, nonce = encrypt_message(original_message)

    assert ciphertext != original_message
    assert len(nonce) == 24  # 12-byte nonce represented as hex
    assert decrypt_message(ciphertext, nonce) == original_message


def test_encryption_uses_different_nonces():
    """Encrypting the same message twice should use fresh nonces."""
    message = "Repeated message"

    ciphertext1, nonce1 = encrypt_message(message)
    ciphertext2, nonce2 = encrypt_message(message)

    assert nonce1 != nonce2
    assert ciphertext1 != ciphertext2


def test_tampered_ciphertext_is_rejected():
    """AES-GCM must reject ciphertext that has been modified."""
    original_message = "Do not modify this message"
    ciphertext, nonce = encrypt_message(original_message)

    # Change one hexadecimal character in the ciphertext.
    first_char = "0" if ciphertext[0] != "0" else "1"
    tampered_ciphertext = first_char + ciphertext[1:]

    try:
        decrypt_message(tampered_ciphertext, nonce)
    except Exception:
        pass
    else:
        raise AssertionError(
            "Tampered ciphertext was accepted instead of rejected"
        )
