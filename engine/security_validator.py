
import os
from pathlib import Path


class SecurityValidator:

    # Maximum original plaintext size: 100 GiB.
    MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024

    MAX_PASSWORD_LENGTH = 1024
    MIN_PASSWORD_LENGTH = 1

    MIN_CHUNK_SIZE = 1024
    MAX_CHUNK_SIZE = 4 * 1024 * 1024

    MAX_CONTAINER_METADATA_SIZE = 16 * 1024
    MAX_CHUNK_COUNT = 2**32

    # VLT v2 container-format overhead.
    CONTAINER_FIXED_HEADER_SIZE = 59
    CONTAINER_WRAPPED_KEY_SIZE = 48
    CONTAINER_CHUNK_LENGTH_SIZE = 4
    CONTAINER_AUTH_TAG_SIZE = 16

    MAX_CHUNKS_AT_MINIMUM_SIZE = (
        MAX_FILE_SIZE + MIN_CHUNK_SIZE - 1
    ) // MIN_CHUNK_SIZE

    # Maximum encrypted container size, including all overhead.
    MAX_CONTAINER_SIZE = (
        MAX_FILE_SIZE
        + MAX_CHUNKS_AT_MINIMUM_SIZE
        * (
            CONTAINER_CHUNK_LENGTH_SIZE
            + CONTAINER_AUTH_TAG_SIZE
        )
        + CONTAINER_FIXED_HEADER_SIZE
        + CONTAINER_WRAPPED_KEY_SIZE
        + MAX_CONTAINER_METADATA_SIZE
    )

    @classmethod
    def validate_password(cls, password):

        if not isinstance(password, str):
            raise ValueError("Password must be a string")

        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) > cls.MAX_PASSWORD_LENGTH:
            raise ValueError("Password exceeds maximum length")

        return True

    @classmethod
    def _validate_readable_regular_source(
        cls,
        source,
        maximum_size,
        size_error_message
    ):

        path = Path(source)

        if not path.exists():
            raise FileNotFoundError(path)

        if path.is_symlink():
            raise ValueError("Symbolic links are not supported")

        if not path.is_file():
            raise ValueError("Source must be a regular file")

        if not os.access(path, os.R_OK):
            raise PermissionError("Source file is not readable")

        size = path.stat().st_size

        if size > maximum_size:
            raise ValueError(size_error_message)

        return path

    @classmethod
    def validate_source(cls, source):

        return cls._validate_readable_regular_source(
            source,
            cls.MAX_FILE_SIZE,
            "File exceeds maximum supported size"
        )

    @classmethod
    def validate_container_source(cls, source):

        return cls._validate_readable_regular_source(
            source,
            cls.MAX_CONTAINER_SIZE,
            "Container exceeds maximum supported size"
        )

    @classmethod
    def validate_destination(cls, destination):

        path = Path(destination)

        if not path.parent.exists():
            raise FileNotFoundError(
                "Destination directory does not exist"
            )

        if not path.parent.is_dir():
            raise NotADirectoryError(
                "Destination parent must be a directory"
            )

        if path.exists() or path.is_symlink():
            raise FileExistsError(
                "Destination already exists"
            )

        if path.parent.is_symlink():
            raise ValueError(
                "Symbolic link destination directories are not supported"
            )

        if path.name in ("", ".", ".."):
            raise ValueError("Invalid destination filename")

        return path

    @classmethod
    def validate_chunk_size(cls, chunk_size):

        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
        ):
            raise ValueError("Chunk size must be an integer")

        if not (
            cls.MIN_CHUNK_SIZE
            <= chunk_size
            <= cls.MAX_CHUNK_SIZE
        ):
            raise ValueError("Chunk size outside permitted limits")

        return True

    @classmethod
    def validate_chunk_count(cls, file_size, chunk_size):

        if (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or file_size < 0
        ):
            raise ValueError("Invalid file size")

        cls.validate_chunk_size(chunk_size)

        chunk_count = (
            file_size + chunk_size - 1
        ) // chunk_size

        if chunk_count > cls.MAX_CHUNK_COUNT:
            raise ValueError("Maximum chunk count exceeded")

        return chunk_count

    @classmethod
    def validate_metadata_size(cls, metadata):

        if not isinstance(metadata, bytes):
            raise ValueError("Metadata must be bytes")

        if not metadata:
            raise ValueError("Metadata cannot be empty")

        if len(metadata) > cls.MAX_CONTAINER_METADATA_SIZE:
            raise ValueError("Metadata exceeds permitted size")

        return True

    @classmethod
    def validate_source_destination(cls, source, destination):

        source_path = Path(source).resolve()
        destination_path = Path(destination).resolve()

        if source_path == destination_path:
            raise ValueError(
                "Source and destination cannot be identical"
            )

        return True
