
import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class KeyManager:

    VERSION = 1

    KEY_LENGTH = 32
    SALT_LENGTH = 16
    NONCE_LENGTH = 12
    TAG_LENGTH = 16

    MEMORY_COST = 65536
    TIME_COST = 3
    PARALLELISM = 4

    MAX_PASSWORD_LENGTH = 1024

    AAD = b"VaultCrypt-512:DEK:V1"

    @classmethod
    def _validate_password(cls, password):
        if not isinstance(password, str):
            raise ValueError("Password must be a string")

        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) > cls.MAX_PASSWORD_LENGTH:
            raise ValueError("Password exceeds maximum allowed length")

    @classmethod
    def _validate_salt(cls, salt):
        if not isinstance(salt, bytes):
            raise ValueError("Salt must be bytes")

        if len(salt) != cls.SALT_LENGTH:
            raise ValueError("Invalid salt")

    @classmethod
    def _validate_nonce(cls, nonce):
        if not isinstance(nonce, bytes):
            raise ValueError("Nonce must be bytes")

        if len(nonce) != cls.NONCE_LENGTH:
            raise ValueError("Invalid nonce")

    @staticmethod
    def _validate_associated_data(associated_data):
        if not isinstance(associated_data, bytes):
            raise ValueError("Associated data must be bytes")

    @classmethod
    def generate_data_key(cls):
        """Generate an independent 256-bit data encryption key."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def derive_master_key(cls, password, salt):
        """Derive a 256-bit key-encryption key using Argon2id."""

        cls._validate_password(password)
        cls._validate_salt(salt)

        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=cls.TIME_COST,
            memory_cost=cls.MEMORY_COST,
            parallelism=cls.PARALLELISM,
            hash_len=cls.KEY_LENGTH,
            type=Type.ID
        )

    @classmethod
    def wrap_data_key(
        cls,
        data_key,
        master_password,
        *,
        associated_data=b"",
        salt=None,
        nonce=None
    ):
        """Encrypt a data encryption key using a password-derived key."""

        if not isinstance(data_key, bytes):
            raise ValueError("Data key must be bytes")

        if len(data_key) != cls.KEY_LENGTH:
            raise ValueError("Data key must be 256 bits")

        cls._validate_password(master_password)
        cls._validate_associated_data(associated_data)

        if salt is None:
            salt = os.urandom(cls.SALT_LENGTH)

        if nonce is None:
            nonce = os.urandom(cls.NONCE_LENGTH)

        cls._validate_salt(salt)
        cls._validate_nonce(nonce)

        master_key = cls.derive_master_key(
            master_password,
            salt
        )

        wrapped_key = AESGCM(master_key).encrypt(
            nonce,
            data_key,
            cls.AAD + associated_data
        )

        return {
            "version": cls.VERSION,
            "salt": salt,
            "nonce": nonce,
            "wrapped_key": wrapped_key
        }

    @classmethod
    def unwrap_data_key(
        cls,
        key_package,
        master_password,
        *,
        associated_data=b""
    ):
        """Recover and authenticate the original data encryption key."""

        if not isinstance(key_package, dict):
            raise ValueError("Invalid key package")

        version = key_package.get("version")

        # Reject bool explicitly because True == 1 in Python.
        if type(version) is not int or version != cls.VERSION:
            raise ValueError("Unsupported key package version")

        salt = key_package.get("salt")
        nonce = key_package.get("nonce")
        wrapped_key = key_package.get("wrapped_key")

        cls._validate_password(master_password)
        cls._validate_salt(salt)
        cls._validate_nonce(nonce)
        cls._validate_associated_data(associated_data)

        if not isinstance(wrapped_key, bytes):
            raise ValueError("Invalid wrapped key")

        if len(wrapped_key) != cls.KEY_LENGTH + cls.TAG_LENGTH:
            raise ValueError("Invalid wrapped key")

        master_key = cls.derive_master_key(
            master_password,
            salt
        )

        try:
            data_key = AESGCM(master_key).decrypt(
                nonce,
                wrapped_key,
                cls.AAD + associated_data
            )

        except InvalidTag as exc:
            raise ValueError(
                "Key recovery failed: incorrect password "
                "or modified key package"
            ) from exc

        if len(data_key) != cls.KEY_LENGTH:
            raise ValueError("Recovered data key has invalid length")

        return data_key
