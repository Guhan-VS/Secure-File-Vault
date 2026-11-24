
import json

import pytest

from engine.container_format import VaultContainerFormat


def valid_metadata():
    return {
        "filename": "document.txt",
        "extension": ".txt",
        "original_size": 1024,
        "chunk_size": 1024,
        "format_version": VaultContainerFormat.VERSION,
    }


# --------------------------------------------------
# METADATA CREATION
# --------------------------------------------------

def test_create_metadata():
    metadata = VaultContainerFormat.create_metadata(
        "document.txt",
        1024,
        1024,
    )

    assert metadata["filename"] == "document.txt"
    assert metadata["extension"] == ".txt"
    assert metadata["original_size"] == 1024
    assert metadata["chunk_size"] == 1024
    assert metadata["format_version"] == 2


def test_metadata_serialization():
    metadata = valid_metadata()

    encoded = VaultContainerFormat.serialize_metadata(metadata)
    decoded = VaultContainerFormat.deserialize_metadata(encoded)

    assert decoded == metadata


def test_filename_preservation():
    metadata = VaultContainerFormat.create_metadata(
        "report.final.pdf",
        2048,
        1024,
    )

    assert metadata["filename"] == "report.final.pdf"
    assert metadata["extension"] == ".pdf"


def test_path_traversal_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "../secret.txt",
            1024,
            1024,
        )


def test_backslash_path_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "..\\secret.txt",
            1024,
            1024,
        )


def test_invalid_extension_rejected():
    metadata = valid_metadata()
    metadata["extension"] = ".pdf"

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_invalid_size_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "document.txt",
            -1,
            1024,
        )


def test_invalid_version_rejected():
    metadata = valid_metadata()
    metadata["format_version"] = 999

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


# --------------------------------------------------
# METADATA STRUCTURE
# --------------------------------------------------

def test_missing_metadata_field_rejected():
    metadata = valid_metadata()
    del metadata["filename"]

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_extra_metadata_field_rejected():
    metadata = valid_metadata()
    metadata["extra"] = "unexpected"

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_non_dictionary_metadata_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata([])


def test_metadata_boolean_size_rejected():
    metadata = valid_metadata()
    metadata["original_size"] = True

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_metadata_boolean_chunk_size_rejected():
    metadata = valid_metadata()
    metadata["chunk_size"] = True

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_metadata_float_size_rejected():
    metadata = valid_metadata()
    metadata["original_size"] = 1024.0

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


def test_metadata_boolean_version_rejected():
    metadata = valid_metadata()
    metadata["format_version"] = True

    with pytest.raises(ValueError):
        VaultContainerFormat.validate_metadata(metadata)


# --------------------------------------------------
# FILENAME VALIDATION
# --------------------------------------------------

@pytest.mark.parametrize(
    "filename",
    [
        "",
        ".",
        "..",
        "../secret.txt",
        "..\\secret.txt",
        "folder/file.txt",
        "folder\\file.txt",
        "invalid\x00name.txt",
    ],
)
def test_invalid_filenames_rejected(filename):
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            filename,
            1024,
            1024,
        )


def test_maximum_filename_length_accepted():
    filename = "a" * 251 + ".txt"

    metadata = VaultContainerFormat.create_metadata(
        filename,
        1024,
        1024,
    )

    assert metadata["filename"] == filename


def test_oversized_filename_rejected():
    filename = "a" * 252 + ".txt"

    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            filename,
            1024,
            1024,
        )


# --------------------------------------------------
# CHUNK SIZE VALIDATION
# --------------------------------------------------

def test_zero_chunk_size_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "document.txt",
            1024,
            0,
        )


def test_negative_chunk_size_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "document.txt",
            1024,
            -1024,
        )


def test_boolean_chunk_size_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.create_metadata(
            "document.txt",
            1024,
            True,
        )


# --------------------------------------------------
# SERIALIZATION AND ENCODING
# --------------------------------------------------

def test_empty_encoded_metadata_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(b"")


def test_non_bytes_encoded_metadata_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(
            '{"filename": "document.txt"}'
        )


def test_invalid_json_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(
            b"{invalid json}"
        )


def test_invalid_utf8_rejected():
    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(
            b"\xff\xfe\xfa"
        )


def test_oversized_metadata_rejected():
    encoded = b"A" * (
        VaultContainerFormat.MAX_METADATA_SIZE + 1
    )

    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(encoded)



def test_oversized_serialized_metadata_rejected():
    metadata = valid_metadata()
    metadata["filename"] = "a" * 251 + ".txt"

    encoded = VaultContainerFormat.serialize_metadata(metadata)

    assert len(encoded) <= VaultContainerFormat.MAX_METADATA_SIZE


# --------------------------------------------------
# MALFORMED JSON ADVERSARIAL CASES
# These tests document current parser behavior.
# They may expose issues requiring an engine fix.
# --------------------------------------------------

def test_duplicate_json_keys_rejected():
    encoded = (
        b'{"filename":"first.txt",'
        b'"filename":"second.txt",'
        b'"extension":".txt",'
        b'"original_size":1024,'
        b'"chunk_size":1024,'
        b'"format_version":2}'
    )

    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(encoded)


@pytest.mark.parametrize(
    "invalid_number",
    [
        b"NaN",
        b"Infinity",
        b"-Infinity",
    ],
)
def test_non_standard_json_numbers_rejected(invalid_number):
    encoded = (
        b'{"filename":"document.txt",'
        b'"extension":".txt",'
        b'"original_size":'
        + invalid_number
        + b',"chunk_size":1024,"format_version":2}'
    )

    with pytest.raises(ValueError):
        VaultContainerFormat.deserialize_metadata(encoded)
