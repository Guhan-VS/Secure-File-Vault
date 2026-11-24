
import os
import stat
import struct
from pathlib import Path

from engine.file_encryption import VaultFileEngine
from engine.container_format import VaultContainerFormat
from engine.key_manager import KeyManager
from engine.security_validator import SecurityValidator


class VaultContainerInspector:

    @classmethod
    def inspect(cls, container_path, password=None):

        path = SecurityValidator.validate_container_source(
            container_path
        )

        with path.open("rb") as file:

            file_stat = os.fstat(file.fileno())

            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError("Container must be a regular file")

            actual_size = file_stat.st_size

            if actual_size > SecurityValidator.MAX_CONTAINER_SIZE:
                raise ValueError(
                    "Container exceeds maximum supported size"
                )

            prefix = VaultFileEngine._read_exact(
                file,
                VaultFileEngine.BASE_HEADER.size
            )

            (
                magic,
                version,
                chunk_size,
                total_size,
                salt,
                wrap_nonce,
                nonce_prefix,
                metadata_length
            ) = VaultFileEngine.BASE_HEADER.unpack(prefix)

            if magic != VaultFileEngine.MAGIC:
                raise ValueError("Invalid vault magic")

            if version != VaultFileEngine.VERSION:
                raise ValueError("Unsupported vault version")

            SecurityValidator.validate_chunk_size(chunk_size)

            if (
                not isinstance(total_size, int)
                or total_size < 0
            ):
                raise ValueError("Invalid original file size")

            if total_size > SecurityValidator.MAX_FILE_SIZE:
                raise ValueError(
                    "File exceeds maximum supported size"
                )

            chunk_count = SecurityValidator.validate_chunk_count(
                total_size,
                chunk_size
            )

            if not (
                1 <= metadata_length
                <= SecurityValidator.MAX_CONTAINER_METADATA_SIZE
            ):
                raise ValueError("Invalid metadata length")

            metadata_bytes = VaultFileEngine._read_exact(
                file,
                metadata_length
            )

            SecurityValidator.validate_metadata_size(metadata_bytes)

            metadata = VaultContainerFormat.deserialize_metadata(
                metadata_bytes
            )

            if metadata["original_size"] != total_size:
                raise ValueError("File size metadata mismatch")

            if metadata["chunk_size"] != chunk_size:
                raise ValueError("Chunk size metadata mismatch")

            wrapped_key = VaultFileEngine._read_exact(
                file,
                SecurityValidator.CONTAINER_WRAPPED_KEY_SIZE
            )

            prefix_and_metadata = prefix + metadata_bytes

            header = prefix_and_metadata + wrapped_key

            expected_size = (
                len(header)
                + chunk_count
                * SecurityValidator.CONTAINER_CHUNK_LENGTH_SIZE
                + total_size
                + chunk_count
                * SecurityValidator.CONTAINER_AUTH_TAG_SIZE
            )

            if actual_size != expected_size:
                raise ValueError(
                    "Container size mismatch or incomplete data"
                )

            # Validate every chunk's declared plaintext length.
            # This is structural validation; chunk contents are not decrypted.
            for index in range(chunk_count):

                expected_length = min(
                    chunk_size,
                    total_size - index * chunk_size
                )

                declared_length = struct.unpack(
                    ">I",
                    VaultFileEngine._read_exact(file, 4)
                )[0]

                if declared_length != expected_length:
                    raise ValueError("Invalid chunk length")

                # Skip encrypted data and its authentication tag.
                file.seek(
                    expected_length
                    + SecurityValidator.CONTAINER_AUTH_TAG_SIZE,
                    os.SEEK_CUR
                )
            authenticated = False

            if password is not None:

                key_package = {
                    "version": KeyManager.VERSION,
                    "salt": salt,
                    "nonce": wrap_nonce,
                    "wrapped_key": wrapped_key
                }

                KeyManager.unwrap_data_key(
                    key_package,
                    password,
                    associated_data=prefix_and_metadata
                )

                authenticated = True

            return {
                "container": path.name,
                "format": "VaultCrypt",
                "version": version,
                "original_filename": metadata["filename"],
                "extension": metadata["extension"],
                "original_size": total_size,
                "chunk_size": chunk_size,
                "chunk_count": chunk_count,
                "container_size": actual_size,
                "metadata_authenticated": authenticated,
                "encryption": "AES-256-GCM",
                "key_derivation": "Argon2id"
            }
