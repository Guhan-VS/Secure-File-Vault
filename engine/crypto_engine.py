
import os
import struct
import hashlib

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class VaultCrypt512:

    MAGIC = b"VLTCR512"
    VERSION = 1

    # Argon2id parameters
    MEMORY_COST = 65536  # KiB
    TIME_COST = 3
    PARALLELISM = 4
    KEY_LENGTH = 32

    SALT_LENGTH = 16
    NONCE_LENGTH = 12
    TAG_LENGTH = 16

    MAX_PASSWORD_LENGTH = 1024

    HEADER = struct.Struct(">8sB16s12s")

    @classmethod
    def _validate_password(cls, password: str) -> None:
        if not isinstance(password, str):
            raise ValueError("Password must be a string")

        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) > cls.MAX_PASSWORD_LENGTH:
            raise ValueError("Password exceeds maximum allowed length")

    @staticmethod
    def _validate_data(data: bytes) -> None:
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes")

    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        cls._validate_password(password)

        if not isinstance(salt, bytes):
            raise ValueError("Salt must be bytes")

        if len(salt) != cls.SALT_LENGTH:
            raise ValueError("Invalid salt")

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
    def encrypt(cls, data: bytes, password: str) -> bytes:
        cls._validate_data(data)
        cls._validate_password(password)

        salt = os.urandom(cls.SALT_LENGTH)
        nonce = os.urandom(cls.NONCE_LENGTH)

        key = cls.derive_key(password, salt)

        header = cls.HEADER.pack(
            cls.MAGIC,
            cls.VERSION,
            salt,
            nonce
        )

        cipher = AESGCM(key)

        ciphertext = cipher.encrypt(
            nonce,
            data,
            header
        )

        return header + ciphertext

    @classmethod
    def decrypt(cls, payload: bytes, password: str) -> bytes:
        if not isinstance(payload, bytes):
            raise ValueError("Encrypted payload must be bytes")

        cls._validate_password(password)

        minimum_length = cls.HEADER.size + cls.TAG_LENGTH

        if len(payload) < minimum_length:
            raise ValueError("Invalid or incomplete vault file")

        header = payload[:cls.HEADER.size]

        try:
            magic, version, salt, nonce = cls.HEADER.unpack(header)
        except struct.error as exc:
            raise ValueError("Invalid vault header") from exc

        if magic != cls.MAGIC:
            raise ValueError("Invalid vault format")

        if version != cls.VERSION:
            raise ValueError("Unsupported vault version")

        key = cls.derive_key(password, salt)

        cipher = AESGCM(key)

        try:
            return cipher.decrypt(
                nonce,
                payload[cls.HEADER.size:],
                header
            )
        except InvalidTag as exc:
            raise ValueError(
                "Authentication failed: wrong password "
                "or modified file"
            ) from exc

    @classmethod
    def fingerprint(cls, data: bytes) -> str:
        cls._validate_data(data)
        return hashlib.sha512(data).hexdigest()
