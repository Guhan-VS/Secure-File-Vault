
import pytest

from engine.crypto_engine import VaultCrypt512


PASSWORD = "StrongPassword!2026"
ORIGINAL = b"VaultCrypt512 security testing"


def test_encryption_decryption():
    encrypted = VaultCrypt512.encrypt(ORIGINAL, PASSWORD)
    decrypted = VaultCrypt512.decrypt(encrypted, PASSWORD)

    assert decrypted == ORIGINAL


def test_wrong_password_rejected():
    encrypted = VaultCrypt512.encrypt(ORIGINAL, PASSWORD)

    with pytest.raises(ValueError):
        VaultCrypt512.decrypt(encrypted, "WrongPassword")


def test_tamper_detection():
    encrypted = bytearray(
        VaultCrypt512.encrypt(ORIGINAL, PASSWORD)
    )

    encrypted[-1] ^= 1

    with pytest.raises(ValueError):
        VaultCrypt512.decrypt(bytes(encrypted), PASSWORD)


def test_fingerprint_length():
    fingerprint = VaultCrypt512.fingerprint(ORIGINAL)

    assert len(fingerprint) == 128


def test_different_encryptions():
    first = VaultCrypt512.encrypt(ORIGINAL, PASSWORD)
    second = VaultCrypt512.encrypt(ORIGINAL, PASSWORD)

    assert first != second


def test_empty_password_rejected_during_encryption():
    with pytest.raises(ValueError):
        VaultCrypt512.encrypt(ORIGINAL, "")


def test_empty_password_rejected_during_decryption():
    encrypted = VaultCrypt512.encrypt(ORIGINAL, PASSWORD)

    with pytest.raises(ValueError):
        VaultCrypt512.decrypt(encrypted, "")


def test_non_string_password_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.encrypt(ORIGINAL, 12345)


def test_oversized_password_rejected():
    password = "A" * (VaultCrypt512.MAX_PASSWORD_LENGTH + 1)

    with pytest.raises(ValueError):
        VaultCrypt512.encrypt(ORIGINAL, password)


def test_non_bytes_data_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.encrypt("plain text", PASSWORD)


def test_non_bytes_payload_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.decrypt("invalid payload", PASSWORD)


def test_truncated_payload_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.decrypt(b"short", PASSWORD)


def test_invalid_magic_rejected():
    encrypted = bytearray(
        VaultCrypt512.encrypt(ORIGINAL, PASSWORD)
    )

    encrypted[0] ^= 1

    with pytest.raises(ValueError, match="Invalid vault format"):
        VaultCrypt512.decrypt(bytes(encrypted), PASSWORD)


def test_unsupported_version_rejected():
    encrypted = bytearray(
        VaultCrypt512.encrypt(ORIGINAL, PASSWORD)
    )

    encrypted[8] = 99

    with pytest.raises(ValueError, match="Unsupported vault version"):
        VaultCrypt512.decrypt(bytes(encrypted), PASSWORD)


def test_invalid_salt_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.derive_key(PASSWORD, b"short")


def test_non_bytes_salt_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.derive_key(PASSWORD, "invalid salt")


def test_empty_data_encryption_decryption():
    encrypted = VaultCrypt512.encrypt(b"", PASSWORD)
    decrypted = VaultCrypt512.decrypt(encrypted, PASSWORD)

    assert decrypted == b""


def test_fingerprint_non_bytes_rejected():
    with pytest.raises(ValueError):
        VaultCrypt512.fingerprint("plain text")
