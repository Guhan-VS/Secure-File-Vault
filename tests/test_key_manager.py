
import pytest

from engine.key_manager import KeyManager


PASSWORD = "StrongPassword2026!"


def test_key_generation():
    key = KeyManager.generate_data_key()

    assert isinstance(key, bytes)
    assert len(key) == 32


def test_key_wrapping_and_recovery():
    data_key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        data_key,
        PASSWORD
    )

    recovered = KeyManager.unwrap_data_key(
        package,
        PASSWORD
    )

    assert recovered == data_key


def test_wrong_password():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        key,
        "CorrectPassword"
    )

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            package,
            "WrongPassword"
        )


def test_randomized_key_wrapping():
    key = KeyManager.generate_data_key()

    first = KeyManager.wrap_data_key(key, "Password123")
    second = KeyManager.wrap_data_key(key, "Password123")

    assert first["salt"] != second["salt"]
    assert first["nonce"] != second["nonce"]
    assert first["wrapped_key"] != second["wrapped_key"]


def test_modified_key_package():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(key, "Password123")

    modified = package.copy()
    modified["wrapped_key"] = (
        bytes([modified["wrapped_key"][0] ^ 1])
        + modified["wrapped_key"][1:]
    )

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            modified,
            "Password123"
        )


def test_empty_password_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(key, "")


def test_non_string_password_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(key, 12345)


def test_oversized_password_rejected():
    key = KeyManager.generate_data_key()
    password = "A" * (KeyManager.MAX_PASSWORD_LENGTH + 1)

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(key, password)


def test_empty_password_rejected_during_recovery():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, "")


def test_invalid_data_key_length_rejected():
    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(b"short", PASSWORD)


def test_non_bytes_data_key_rejected():
    with pytest.raises(ValueError):
        KeyManager.wrap_data_key("invalid", PASSWORD)


def test_invalid_salt_length_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(
            key,
            PASSWORD,
            salt=b"short"
        )


def test_non_bytes_salt_rejected():
    with pytest.raises(ValueError):
        KeyManager.derive_master_key(PASSWORD, "invalid")


def test_invalid_nonce_length_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(
            key,
            PASSWORD,
            nonce=b"short"
        )


def test_non_bytes_nonce_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(
            key,
            PASSWORD,
            nonce="invalid"
        )


def test_invalid_associated_data_rejected():
    key = KeyManager.generate_data_key()

    with pytest.raises(ValueError):
        KeyManager.wrap_data_key(
            key,
            PASSWORD,
            associated_data="invalid"
        )


def test_associated_data_authentication():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        key,
        PASSWORD,
        associated_data=b"original-header"
    )

    recovered = KeyManager.unwrap_data_key(
        package,
        PASSWORD,
        associated_data=b"original-header"
    )

    assert recovered == key


def test_modified_associated_data_rejected():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        key,
        PASSWORD,
        associated_data=b"original-header"
    )

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            package,
            PASSWORD,
            associated_data=b"modified-header"
        )


def test_invalid_package_rejected():
    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            "invalid",
            PASSWORD
        )


def test_missing_package_fields_rejected():
    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            {"version": KeyManager.VERSION},
            PASSWORD
        )


def test_unsupported_package_version_rejected():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    package["version"] = 99

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, PASSWORD)


def test_boolean_package_version_rejected():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    package["version"] = True

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, PASSWORD)


def test_invalid_wrapped_key_length_rejected():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    package["wrapped_key"] = b"short"

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, PASSWORD)


def test_non_bytes_wrapped_key_rejected():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    package["wrapped_key"] = "invalid"

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, PASSWORD)


def test_modified_salt_rejected():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        key,
        PASSWORD
    )

    modified = package.copy()

    modified_salt = bytearray(modified["salt"])
    modified_salt[0] ^= 1

    modified["salt"] = bytes(modified_salt)

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            modified,
            PASSWORD
        )


def test_modified_nonce_rejected():
    key = KeyManager.generate_data_key()

    package = KeyManager.wrap_data_key(
        key,
        PASSWORD
    )

    modified = package.copy()

    modified_nonce = bytearray(modified["nonce"])
    modified_nonce[0] ^= 1

    modified["nonce"] = bytes(modified_nonce)

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            modified,
            PASSWORD
        )

def test_non_string_password_rejected_during_recovery():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(package, 12345)


def test_oversized_password_rejected_during_recovery():
    key = KeyManager.generate_data_key()
    package = KeyManager.wrap_data_key(key, PASSWORD)

    oversized_password = "A" * (
        KeyManager.MAX_PASSWORD_LENGTH + 1
    )

    with pytest.raises(ValueError):
        KeyManager.unwrap_data_key(
            package,
            oversized_password
        )