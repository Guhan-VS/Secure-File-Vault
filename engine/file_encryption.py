
import hashlib
import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from engine.key_manager import KeyManager
from engine.container_format import VaultContainerFormat
from engine.security_validator import SecurityValidator


class VaultFileEngine:

    MAGIC = b"VLTCR512"
    VERSION = 2

    DEFAULT_CHUNK_SIZE = 1024 * 1024
    MIN_CHUNK_SIZE = 1024
    MAX_CHUNK_SIZE = 4 * 1024 * 1024

    NONCE_PREFIX_SIZE = 8
    TAG_SIZE = 16

    BASE_HEADER = struct.Struct(">8sBIQ16s12s8sH")

    MAX_METADATA_SIZE = VaultContainerFormat.MAX_METADATA_SIZE

    @classmethod
    def _read_exact(cls, file, size):

        data = file.read(size)

        if len(data) != size:
            raise ValueError("Truncated or incomplete vault file")

        return data

    @staticmethod
    def _file_signature(stat_result):

        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            stat_result.st_ctime_ns
        )

    @staticmethod
    def _path_signature(stat_result):
        """Return path metadata, including the file identity on Windows."""
        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            stat_result.st_ctime_ns,
        )

    @classmethod
    def _capture_source_snapshot(cls, source):
        """Capture source-path metadata before validation."""
        source = Path(source)

        try:
            return cls._path_signature(source.lstat())
        except OSError as exc:
            raise ValueError(
                "Source file is unavailable before validation"
            ) from exc

    @classmethod
    def _verify_source_snapshot(
        cls,
        source,
        original_signature,
        source_type="file"
    ):
        """Ensure the source path has not changed since the snapshot."""
        try:
            current_signature = cls._path_signature(
                Path(source).lstat()
            )
        except OSError as exc:
            raise ValueError(
                f"Source {source_type} disappeared during validation"
            ) from exc

        if current_signature != original_signature:
            raise ValueError(
                f"Source {source_type} was replaced during validation"
            )

    @classmethod
    def _calculate_file_hash(cls, file):

        digest = hashlib.sha512()

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

        return digest.digest()

    @classmethod
    def _verify_source_unchanged(
        cls,
        source,
        src,
        original_signature,
        original_path_signature,
        original_hash,
        encryption_hash
    ):

        current_signature = cls._file_signature(
            os.fstat(src.fileno())
        )

        if current_signature != original_signature:
            raise ValueError(
                "Source file metadata changed during encryption"
            )

        try:
            current_path_signature = cls._path_signature(
                source.stat()
            )
        except OSError as exc:
            raise ValueError(
                "Source file disappeared during encryption"
            ) from exc

        if current_path_signature != original_path_signature:
            raise ValueError(
                "Source file was replaced or modified during encryption"
            )

        if original_hash != encryption_hash.digest():
            raise ValueError(
                "Source file content changed during encryption"
            )

    @classmethod
    def _verify_container_unchanged(
        cls,
        source,
        src,
        original_signature,
        original_path_signature,
        original_hash
    ):

        current_signature = cls._file_signature(
            os.fstat(src.fileno())
        )

        if current_signature != original_signature:
            raise ValueError(
                "Source container metadata changed during decryption"
            )

        try:
            current_path_signature = cls._path_signature(
                source.stat()
            )
        except OSError as exc:
            raise ValueError(
                "Source container disappeared during decryption"
            ) from exc

        if current_path_signature != original_path_signature:
            raise ValueError(
                "Source container was replaced or modified during decryption"
            )

        src.seek(0)

        current_hash = cls._calculate_file_hash(src)

        src.seek(0)

        if current_hash != original_hash:
            raise ValueError(
                "Source container content changed during decryption"
            )

    @classmethod
    def _create_output(cls, destination):

        destination = Path(destination)

        if not destination.parent.is_dir():
            raise FileNotFoundError(
                "Destination directory does not exist"
            )

        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)

        fd, temp_path = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent
        )

        return destination, fd, Path(temp_path)

    @classmethod
    def _finalize_output(cls, temp_path, destination):

        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)

        # Atomically create the destination without overwriting
        # an existing file.
        os.link(temp_path, destination)

        try:
            os.unlink(temp_path)

        except BaseException as original_error:

            # The hard link was created by this operation.
            # Remove the destination only if it still refers
            # to the same file as our temporary file.
            try:
                temp_stat = os.stat(
                    temp_path,
                    follow_symlinks=False
                )

                destination_stat = os.stat(
                    destination,
                    follow_symlinks=False
                )

                same_file = (
                    temp_stat.st_dev == destination_stat.st_dev
                    and temp_stat.st_ino == destination_stat.st_ino
                )

                if same_file:
                    os.unlink(destination)

            except FileNotFoundError:
                pass

            except OSError as cleanup_error:
                original_error.add_note(
                    "Destination rollback failed: "
                    f"{cleanup_error}"
                )

            raise

    @staticmethod
    def _cleanup_failed_output(fd, temp_path, original_error):
        """
        Clean up failed output without hiding the original exception.

        The descriptor is closed only if ownership was not transferred
        to a file object. Temporary-file deletion is attempted regardless.
        """

        if fd is not None:
            try:
                os.close(fd)
            except OSError as cleanup_error:
                original_error.add_note(
                    f"Temporary file descriptor cleanup failed: "
                    f"{cleanup_error}"
                )

        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            original_error.add_note(
                f"Temporary file cleanup failed: {cleanup_error}"
            )

    @classmethod
    def encrypt_file(
        cls,
        source,
        destination,
        password,
        chunk_size=DEFAULT_CHUNK_SIZE
    ):

        source_snapshot = cls._capture_source_snapshot(source)

        source = SecurityValidator.validate_source(source)

        cls._verify_source_snapshot(
            source,
            source_snapshot,
            "file"
        )

        SecurityValidator.validate_password(password)
        SecurityValidator.validate_chunk_size(chunk_size)

        SecurityValidator.validate_source_destination(
            source,
            destination
        )

        destination = SecurityValidator.validate_destination(
            destination
        )

        destination, fd, temp_path = cls._create_output(destination)

        try:

            with source.open("rb") as src:
                
                # Verify the path still matches the pre-validation snapshot.
                # Keep path metadata comparisons separate from fstat() on Windows.
                cls._verify_source_snapshot(
                    source,
                    source_snapshot,
                    "file"
                )

                initial_stat = os.fstat(src.fileno())
                original_signature = cls._file_signature(
                    initial_stat
                )

                original_path_signature = cls._path_signature(
                    source.stat()
                )

                total_size = initial_stat.st_size

                if total_size > SecurityValidator.MAX_FILE_SIZE:
                    raise ValueError(
                        "File exceeds maximum supported size"
                    )

                chunk_count = SecurityValidator.validate_chunk_count(
                    total_size,
                    chunk_size
                )

                original_hash = cls._calculate_file_hash(src)

                if (
                    cls._file_signature(os.fstat(src.fileno()))
                    != original_signature
                ):
                    raise ValueError(
                        "Source file changed during initial hashing"
                    )

                src.seek(0)

                metadata = VaultContainerFormat.create_metadata(
                    filename=source.name,
                    original_size=total_size,
                    chunk_size=chunk_size
                )

                metadata_bytes = (
                    VaultContainerFormat.serialize_metadata(metadata)
                )

                SecurityValidator.validate_metadata_size(
                    metadata_bytes
                )

                salt = os.urandom(16)
                wrap_nonce = os.urandom(12)
                nonce_prefix = os.urandom(cls.NONCE_PREFIX_SIZE)

                data_key = KeyManager.generate_data_key()

                prefix = cls.BASE_HEADER.pack(
                    cls.MAGIC,
                    cls.VERSION,
                    chunk_size,
                    total_size,
                    salt,
                    wrap_nonce,
                    nonce_prefix,
                    len(metadata_bytes)
                )

                authenticated_header = prefix + metadata_bytes

                key_package = KeyManager.wrap_data_key(
                    data_key,
                    password,
                    associated_data=authenticated_header,
                    salt=salt,
                    nonce=wrap_nonce
                )

                header = (
                    authenticated_header
                    + key_package["wrapped_key"]
                )

                cipher = AESGCM(data_key)

                encryption_hash = hashlib.sha512()

                with os.fdopen(fd, "wb") as out:
                    fd = None

                    out.write(header)

                    for index in range(chunk_count):

                        expected_length = min(
                            chunk_size,
                            total_size - index * chunk_size
                        )

                        chunk = cls._read_exact(
                            src,
                            expected_length
                        )

                        encryption_hash.update(chunk)

                        nonce = (
                            nonce_prefix
                            + index.to_bytes(4, "big")
                        )

                        aad = (
                            header
                            + struct.pack(
                                ">QI",
                                index,
                                expected_length
                            )
                        )

                        encrypted_chunk = cipher.encrypt(
                            nonce,
                            chunk,
                            aad
                        )

                        out.write(
                            struct.pack(">I", expected_length)
                        )

                        out.write(encrypted_chunk)

                    if src.read(1):
                        raise ValueError(
                            "Source file size changed during encryption"
                        )

                    cls._verify_source_unchanged(
                        source,
                        src,
                        original_signature,
                        original_path_signature,
                        original_hash,
                        encryption_hash
                    )

                    out.flush()
                    os.fsync(out.fileno())

            cls._finalize_output(temp_path, destination)

        except BaseException as exc:
            cls._cleanup_failed_output(fd, temp_path, exc)
            raise

        return destination

    @classmethod
    def decrypt_file(
        cls,
        source,
        destination,
        password
    ):

        source_snapshot = cls._capture_source_snapshot(source)

        source = SecurityValidator.validate_container_source(source)

        cls._verify_source_snapshot(
            source,
            source_snapshot,
            "container"
        )

        SecurityValidator.validate_password(password)

        SecurityValidator.validate_source_destination(
            source,
            destination
        )

        destination = SecurityValidator.validate_destination(
            destination
        )

        destination, fd, temp_path = cls._create_output(destination)

        try:

            with source.open("rb") as src, os.fdopen(fd, "wb") as out:
                fd = None

                # Verify the path still matches the pre-validation snapshot.
                # Keep path metadata comparisons separate from fstat() on Windows.
                cls._verify_source_snapshot(
                    source,
                    source_snapshot,
                    "container"
                )

                # Capture the opened file's metadata independently.
                initial_stat = os.fstat(src.fileno())
                original_signature = cls._file_signature(
                    initial_stat
                )

                original_path_signature = cls._path_signature(
                    source.stat()
                )

                # Hash the complete encrypted container before decryption.
                original_hash = cls._calculate_file_hash(src)

                # Ensure it did not change during initial hashing.
                if (
                    cls._file_signature(os.fstat(src.fileno()))
                    != original_signature
                ):
                    raise ValueError(
                        "Source container changed during initial hashing"
                    )

                try:
                    current_path_signature = cls._path_signature(
                        source.stat()
                    )
                except OSError as exc:
                    raise ValueError(
                        "Source container disappeared during initial hashing"
                    ) from exc

                if current_path_signature != original_path_signature:
                    raise ValueError(
                        "Source container was replaced or modified during initial hashing"
                    )

                src.seek(0)

                prefix = cls._read_exact(
                    src,
                    cls.BASE_HEADER.size
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
                ) = cls.BASE_HEADER.unpack(prefix)

                if magic != cls.MAGIC:
                    raise ValueError("Invalid vault format")

                if version != cls.VERSION:
                    raise ValueError("Unsupported vault version")

                if total_size > SecurityValidator.MAX_FILE_SIZE:
                    raise ValueError(
                        "File exceeds maximum supported size"
                    )

                SecurityValidator.validate_chunk_size(chunk_size)

                if not 1 <= metadata_length <= cls.MAX_METADATA_SIZE:
                    raise ValueError("Invalid metadata length")

                metadata_bytes = cls._read_exact(
                    src,
                    metadata_length
                )

                SecurityValidator.validate_metadata_size(
                    metadata_bytes
                )

                metadata = VaultContainerFormat.deserialize_metadata(
                    metadata_bytes
                )

                if metadata["original_size"] != total_size:
                    raise ValueError("File size metadata mismatch")

                if metadata["chunk_size"] != chunk_size:
                    raise ValueError("Chunk size metadata mismatch")

                authenticated_header = prefix + metadata_bytes

                wrapped_key = cls._read_exact(
                    src,
                    32 + cls.TAG_SIZE
                )

                header = authenticated_header + wrapped_key

                key_package = {
                    "version": KeyManager.VERSION,
                    "salt": salt,
                    "nonce": wrap_nonce,
                    "wrapped_key": wrapped_key
                }

                data_key = KeyManager.unwrap_data_key(
                    key_package,
                    password,
                    associated_data=authenticated_header
                )

                cipher = AESGCM(data_key)

                chunk_count = SecurityValidator.validate_chunk_count(
                    total_size,
                    chunk_size
                )

                for index in range(chunk_count):

                    expected_length = min(
                        chunk_size,
                        total_size - index * chunk_size
                    )

                    declared_length = struct.unpack(
                        ">I",
                        cls._read_exact(src, 4)
                    )[0]

                    if declared_length != expected_length:
                        raise ValueError("Invalid chunk length")

                    encrypted_chunk = cls._read_exact(
                        src,
                        expected_length + cls.TAG_SIZE
                    )

                    nonce = (
                        nonce_prefix
                        + index.to_bytes(4, "big")
                    )

                    aad = (
                        header
                        + struct.pack(
                            ">QI",
                            index,
                            expected_length
                        )
                    )

                    try:

                        plaintext = cipher.decrypt(
                            nonce,
                            encrypted_chunk,
                            aad
                        )

                    except InvalidTag as exc:

                        raise ValueError(
                            f"Chunk {index} authentication failed"
                        ) from exc

                    out.write(plaintext)

                if src.read(1):
                    raise ValueError("Unexpected trailing data")

                # Verify the encrypted source before publishing plaintext.
                cls._verify_container_unchanged(
                    source,
                    src,
                    original_signature,
                    original_path_signature,
                    original_hash
                )

                out.flush()
                os.fsync(out.fileno())

            cls._finalize_output(temp_path, destination)

        except BaseException as exc:
            cls._cleanup_failed_output(fd, temp_path, exc)
            raise

        return destination
