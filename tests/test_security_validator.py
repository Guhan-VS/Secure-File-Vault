
import pytest

from engine.security_validator import SecurityValidator


# --------------------------------------------------
# PASSWORD VALIDATION
# --------------------------------------------------

def test_valid_password():
    assert SecurityValidator.validate_password(
        "StrongPassword2026!"
    )


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_password("")


def test_oversized_password_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_password("A" * 1025)


def test_maximum_password_length_accepted():
    assert SecurityValidator.validate_password(
        "A" * SecurityValidator.MAX_PASSWORD_LENGTH
    )


def test_non_string_password_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_password(123456)


def test_none_password_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_password(None)


# --------------------------------------------------
# SOURCE VALIDATION
# --------------------------------------------------

def test_valid_source(tmp_path):
    source = tmp_path / "test.txt"
    source.write_bytes(b"Test data")

    result = SecurityValidator.validate_source(source)

    assert result == source


def test_missing_source_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        SecurityValidator.validate_source(
            tmp_path / "missing.txt"
        )


def test_directory_as_source_rejected(tmp_path):
    with pytest.raises(ValueError):
        SecurityValidator.validate_source(tmp_path)


def test_zero_byte_source_accepted(tmp_path):
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")

    result = SecurityValidator.validate_source(source)

    assert result == source


# --------------------------------------------------
# DESTINATION VALIDATION
# --------------------------------------------------

def test_valid_destination(tmp_path):
    destination = tmp_path / "output.vlt"

    result = SecurityValidator.validate_destination(destination)

    assert result == destination


def test_existing_destination_rejected(tmp_path):
    destination = tmp_path / "output.vlt"
    destination.write_bytes(b"Existing")

    with pytest.raises(FileExistsError):
        SecurityValidator.validate_destination(destination)


def test_missing_destination_directory_rejected(tmp_path):
    destination = tmp_path / "missing" / "output.vlt"

    with pytest.raises(FileNotFoundError):
        SecurityValidator.validate_destination(destination)


# --------------------------------------------------
# CHUNK SIZE VALIDATION
# --------------------------------------------------

def test_invalid_chunk_size_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_size(100)


def test_valid_minimum_chunk_size():
    assert SecurityValidator.validate_chunk_size(
        SecurityValidator.MIN_CHUNK_SIZE
    )


def test_valid_maximum_chunk_size():
    assert SecurityValidator.validate_chunk_size(
        SecurityValidator.MAX_CHUNK_SIZE
    )


@pytest.mark.parametrize(
    "chunk_size",
    [
        0,
        -1,
        100,
        SecurityValidator.MIN_CHUNK_SIZE - 1,
        SecurityValidator.MAX_CHUNK_SIZE + 1,
    ],
)
def test_out_of_range_chunk_sizes_rejected(chunk_size):
    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_size(chunk_size)


@pytest.mark.parametrize(
    "chunk_size",
    [
        True,
        False,
        1024.0,
        "1024",
        None,
    ],
)
def test_invalid_chunk_size_types_rejected(chunk_size):
    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_size(chunk_size)


# --------------------------------------------------
# CHUNK COUNT VALIDATION
# --------------------------------------------------

def test_chunk_count():
    count = SecurityValidator.validate_chunk_count(
        3000, 1024
    )

    assert count == 3


def test_zero_byte_file_has_zero_chunks():
    count = SecurityValidator.validate_chunk_count(
        0, 1024
    )

    assert count == 0


def test_exact_chunk_boundary():
    count = SecurityValidator.validate_chunk_count(
        2048, 1024
    )

    assert count == 2


def test_one_byte_over_chunk_boundary():
    count = SecurityValidator.validate_chunk_count(
        2049, 1024
    )

    assert count == 3


def test_single_byte_file_requires_one_chunk():
    count = SecurityValidator.validate_chunk_count(
        1, 1024
    )

    assert count == 1


def test_maximum_supported_file_size_chunk_count():
    count = SecurityValidator.validate_chunk_count(
        SecurityValidator.MAX_FILE_SIZE,
        SecurityValidator.MIN_CHUNK_SIZE,
    )

    expected = (
        SecurityValidator.MAX_FILE_SIZE
        + SecurityValidator.MIN_CHUNK_SIZE
        - 1
    ) // SecurityValidator.MIN_CHUNK_SIZE

    assert count == expected


def test_maximum_chunk_count_accepted():
    file_size = (
        SecurityValidator.MAX_CHUNK_COUNT
        * SecurityValidator.MIN_CHUNK_SIZE
    )

    count = SecurityValidator.validate_chunk_count(
        file_size,
        SecurityValidator.MIN_CHUNK_SIZE,
    )

    assert count == SecurityValidator.MAX_CHUNK_COUNT


def test_chunk_count_exceeding_limit_rejected():
    file_size = (
        SecurityValidator.MAX_CHUNK_COUNT
        * SecurityValidator.MIN_CHUNK_SIZE
        + 1
    )

    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_count(
            file_size,
            SecurityValidator.MIN_CHUNK_SIZE,
        )


def test_negative_file_size_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_count(
            -100, 1024
        )


@pytest.mark.parametrize(
    "file_size",
    [
        True,
        False,
        1024.0,
        "1024",
        None,
    ],
)
def test_invalid_file_size_types_rejected(file_size):
    with pytest.raises(ValueError):
        SecurityValidator.validate_chunk_count(
            file_size, 1024
        )


# --------------------------------------------------
# METADATA SIZE VALIDATION
# --------------------------------------------------

def test_metadata_size():
    assert SecurityValidator.validate_metadata_size(
        b"VaultCrypt metadata"
    )


def test_empty_metadata_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_metadata_size(b"")


def test_maximum_metadata_size_accepted():
    metadata = b"A" * SecurityValidator.MAX_CONTAINER_METADATA_SIZE

    assert SecurityValidator.validate_metadata_size(metadata)


def test_metadata_exceeding_maximum_rejected():
    metadata = (
        b"A" * (SecurityValidator.MAX_CONTAINER_METADATA_SIZE + 1)
    )

    with pytest.raises(ValueError):
        SecurityValidator.validate_metadata_size(metadata)


def test_non_bytes_metadata_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_metadata_size(
            "VaultCrypt metadata"
        )


def test_none_metadata_rejected():
    with pytest.raises(ValueError):
        SecurityValidator.validate_metadata_size(None)


# --------------------------------------------------
# SOURCE AND DESTINATION VALIDATION
# --------------------------------------------------

def test_source_destination_same_path_rejected(tmp_path):
    source = tmp_path / "file.txt"
    source.write_bytes(b"Test")

    with pytest.raises(ValueError):
        SecurityValidator.validate_source_destination(
            source, source
        )


def test_source_destination_different_paths_accepted(tmp_path):
    source = tmp_path / "source.txt"
    destination = tmp_path / "destination.vlt"

    source.write_bytes(b"Test")

    assert SecurityValidator.validate_source_destination(
        source, destination
    )


def test_source_destination_same_resolved_path_rejected(tmp_path):
    source = tmp_path / "file.txt"
    source.write_bytes(b"Test")

    destination = tmp_path / "." / "file.txt"

    with pytest.raises(ValueError):
        SecurityValidator.validate_source_destination(
            source, destination
        )

# --------------------------------------------------
# CONTAINER SIZE VALIDATION
# --------------------------------------------------

def test_maximum_container_size_formula():

    expected_chunks = (
        SecurityValidator.MAX_FILE_SIZE
        + SecurityValidator.MIN_CHUNK_SIZE
        - 1
    ) // SecurityValidator.MIN_CHUNK_SIZE

    expected_size = (
        SecurityValidator.MAX_FILE_SIZE
        + expected_chunks * 20
        + 59
        + 48
        + SecurityValidator.MAX_CONTAINER_METADATA_SIZE
    )

    assert (
        SecurityValidator.MAX_CHUNKS_AT_MINIMUM_SIZE
        == expected_chunks
    )

    assert SecurityValidator.MAX_CONTAINER_SIZE == expected_size


def test_container_size_is_larger_than_plaintext_limit():

    assert (
        SecurityValidator.MAX_CONTAINER_SIZE
        > SecurityValidator.MAX_FILE_SIZE
    )


def test_valid_container_source(tmp_path):

    container = tmp_path / "test.vlt"
    container.write_bytes(b"VLT container")

    result = SecurityValidator.validate_container_source(
        container
    )

    assert result == container


def test_container_source_accepts_size_above_plaintext_limit(
    tmp_path,
    monkeypatch
):

    container = tmp_path / "test.vlt"
    container.write_bytes(b"A" * 20)

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_FILE_SIZE",
        10
    )

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_CONTAINER_SIZE",
        30
    )

    assert SecurityValidator.validate_container_source(
        container
    ) == container


def test_container_source_rejects_size_above_container_limit(
    tmp_path,
    monkeypatch
):

    container = tmp_path / "large.vlt"
    container.write_bytes(b"A" * 20)

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_CONTAINER_SIZE",
        10
    )

    with pytest.raises(
        ValueError,
        match="Container exceeds maximum"
    ):
        SecurityValidator.validate_container_source(container)


def test_plaintext_source_still_uses_plaintext_limit(
    tmp_path,
    monkeypatch
):

    source = tmp_path / "large.txt"
    source.write_bytes(b"A" * 20)

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_FILE_SIZE",
        10
    )

    with pytest.raises(
        ValueError,
        match="File exceeds maximum"
    ):
        SecurityValidator.validate_source(source)
