
import json
from pathlib import PurePath


class VaultContainerFormat:

    MAGIC = b"VLTCR512"
    VERSION = 2

    MAX_METADATA_SIZE = 16 * 1024
    MAX_FILENAME_LENGTH = 255

    REQUIRED_FIELDS = {
        "filename",
        "extension",
        "original_size",
        "chunk_size",
        "format_version"
    }

    @classmethod
    def create_metadata(
        cls,
        filename,
        original_size,
        chunk_size
    ):
        filename = str(filename)

        if not filename or len(filename) > cls.MAX_FILENAME_LENGTH:
            raise ValueError("Invalid filename")

        if filename in (".", ".."):
            raise ValueError("Invalid filename")

        if "/" in filename or "\\" in filename:
            raise ValueError("Filename must not contain paths")

        if "\x00" in filename:
            raise ValueError("Invalid filename")

        if (
            not isinstance(original_size, int)
            or isinstance(original_size, bool)
            or original_size < 0
        ):
            raise ValueError("Invalid file size")

        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or not 1024 <= chunk_size <= 4 * 1024 * 1024
        ):
            raise ValueError("Invalid chunk size")

        extension = PurePath(filename).suffix

        metadata = {
            "filename": filename,
            "extension": extension,
            "original_size": original_size,
            "chunk_size": chunk_size,
            "format_version": cls.VERSION
        }

        return metadata

    @classmethod
    def serialize_metadata(cls, metadata):
        cls.validate_metadata(metadata)

        encoded = json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False
        ).encode("utf-8")

        if len(encoded) > cls.MAX_METADATA_SIZE:
            raise ValueError("Metadata exceeds maximum size")

        return encoded

    @classmethod
    def _reject_duplicate_keys(cls, pairs):
        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate metadata key")

            result[key] = value

        return result

    @classmethod
    def _reject_nonstandard_constant(cls, value):
        raise ValueError("Invalid JSON numeric constant")

    @classmethod
    def deserialize_metadata(cls, encoded):
        if not isinstance(encoded, bytes):
            raise ValueError("Metadata must be bytes")

        if not encoded or len(encoded) > cls.MAX_METADATA_SIZE:
            raise ValueError("Invalid metadata size")

        try:
            metadata = json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=cls._reject_duplicate_keys,
                parse_constant=cls._reject_nonstandard_constant
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid metadata encoding") from exc

        cls.validate_metadata(metadata)

        return metadata

    @classmethod
    def validate_metadata(cls, metadata):
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be an object")

        if set(metadata.keys()) != cls.REQUIRED_FIELDS:
            raise ValueError("Invalid metadata fields")

        filename = metadata["filename"]
        extension = metadata["extension"]
        original_size = metadata["original_size"]
        chunk_size = metadata["chunk_size"]
        version = metadata["format_version"]

        if not isinstance(filename, str):
            raise ValueError("Invalid filename")

        if not filename or len(filename) > cls.MAX_FILENAME_LENGTH:
            raise ValueError("Invalid filename")

        if filename in (".", ".."):
            raise ValueError("Invalid filename")

        if "/" in filename or "\\" in filename or "\x00" in filename:
            raise ValueError("Unsafe filename")

        if not isinstance(extension, str):
            raise ValueError("Invalid extension")

        if extension != PurePath(filename).suffix:
            raise ValueError("Filename extension mismatch")

        if (
            not isinstance(original_size, int)
            or isinstance(original_size, bool)
            or original_size < 0
        ):
            raise ValueError("Invalid original file size")

        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or not 1024 <= chunk_size <= 4 * 1024 * 1024
        ):
            raise ValueError("Invalid chunk size")

        if type(version) is not int or version != cls.VERSION:
            raise ValueError("Unsupported metadata version")

        return True
