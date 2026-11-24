
import pytest

from engine.file_encryption import VaultFileEngine
from engine.container_inspector import VaultContainerInspector
from engine.security_validator import SecurityValidator


PASSWORD = "StrongVaultPassword!2026"


def create_encrypted_file(tmp_path, content=b"Test data"):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(content)

    VaultFileEngine.encrypt_file(
        original, encrypted, PASSWORD
    )

    return original, encrypted


def read_header(data):
    return list(
        VaultFileEngine.BASE_HEADER.unpack(
            data[:VaultFileEngine.BASE_HEADER.size]
        )
    )


def write_header(data, fields):
    data[:VaultFileEngine.BASE_HEADER.size] = (
        VaultFileEngine.BASE_HEADER.pack(*fields)
    )
    return data


# --------------------------------------------------
# BASIC CONTAINER INSPECTION
# --------------------------------------------------

def test_inspect_container(tmp_path):
    original, encrypted = create_encrypted_file(
        tmp_path, b"Confidential PDF data"
    )

    info = VaultContainerInspector.inspect(encrypted)

    assert info["format"] == "VaultCrypt"
    assert info["version"] == 2
    assert info["original_filename"] == original.name
    assert info["extension"] == ".txt"
    assert info["metadata_authenticated"] is False


def test_inspect_with_password(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Secret document"
    )

    info = VaultContainerInspector.inspect(
        encrypted, PASSWORD
    )

    assert info["metadata_authenticated"] is True


def test_wrong_password_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Secret information"
    )

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(
            encrypted, "WrongPassword"
        )


def test_missing_container_rejected(tmp_path):
    missing = tmp_path / "missing.vlt"

    with pytest.raises(FileNotFoundError):
        VaultContainerInspector.inspect(missing)


# --------------------------------------------------
# HEADER VALIDATION
# --------------------------------------------------

def test_invalid_magic_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    data[0] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(encrypted)


def test_unsupported_version_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)
    fields[1] = VaultFileEngine.VERSION + 1
    encrypted.write_bytes(write_header(data, fields))

    with pytest.raises(ValueError, match="version"):
        VaultContainerInspector.inspect(encrypted)


def test_truncated_base_header_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    encrypted.write_bytes(b"VLTCR512")

    with pytest.raises((ValueError, EOFError)):
        VaultContainerInspector.inspect(encrypted)


def test_truncated_metadata_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = encrypted.read_bytes()
    header_size = VaultFileEngine.BASE_HEADER.size

    encrypted.write_bytes(
        data[:header_size + 5]
    )

    with pytest.raises((ValueError, EOFError)):
        VaultContainerInspector.inspect(encrypted)


def test_truncated_wrapped_key_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = encrypted.read_bytes()
    fields = read_header(data)

    metadata_length = fields[7]
    wrapped_key_start = (
        VaultFileEngine.BASE_HEADER.size + metadata_length
    )

    encrypted.write_bytes(
        data[:wrapped_key_start + 10]
    )

    with pytest.raises((ValueError, EOFError)):
        VaultContainerInspector.inspect(encrypted)


# --------------------------------------------------
# CONTAINER SIZE VALIDATION
# --------------------------------------------------

def test_incomplete_container_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Test information"
    )

    encrypted.write_bytes(
        encrypted.read_bytes()[:-5]
    )

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(encrypted)


def test_header_size_mismatch_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)
    fields[3] += 1

    encrypted.write_bytes(write_header(data, fields))

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(encrypted)


def test_appended_data_rejected_by_inspector(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    with encrypted.open("ab") as file:
        file.write(b"UNEXPECTED DATA")

    with pytest.raises(ValueError, match="Container size"):
        VaultContainerInspector.inspect(encrypted)


def test_oversized_container_rejected_by_inspector(
    tmp_path,
    monkeypatch
):

    _, encrypted = create_encrypted_file(tmp_path)

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_CONTAINER_SIZE",
        10
    )

    with pytest.raises(
        ValueError,
        match="Container exceeds maximum"
    ):
        VaultContainerInspector.inspect(encrypted)


# --------------------------------------------------
# CHUNK VALIDATION
# --------------------------------------------------

def test_chunk_information(tmp_path):
    original = tmp_path / "large.bin"
    encrypted = tmp_path / "large.vlt"

    original.write_bytes(b"A" * 3000)

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD,
        chunk_size=1024
    )

    info = VaultContainerInspector.inspect(encrypted)

    assert info["chunk_size"] == 1024
    assert info["chunk_count"] == 3
    assert info["original_size"] == 3000


def test_invalid_chunk_size_rejected_by_inspector(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)
    fields[2] = 0

    encrypted.write_bytes(write_header(data, fields))

    with pytest.raises(ValueError, match="(?i)chunk size"):
        VaultContainerInspector.inspect(encrypted)


# --------------------------------------------------
# METADATA VALIDATION
# --------------------------------------------------

def test_oversized_metadata_length_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)

    fields[7] = VaultContainerInspector.__dict__.get(
        "MAX_METADATA_SIZE",
        16 * 1024
    ) + 1

    encrypted.write_bytes(write_header(data, fields))

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(encrypted)


def test_zero_metadata_length_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)
    fields[7] = 0

    encrypted.write_bytes(write_header(data, fields))

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(encrypted)


# --------------------------------------------------
# AUTHENTICATION BEHAVIOUR
# --------------------------------------------------

def test_chunk_corruption_does_not_mean_metadata_authentication_failed(
    tmp_path
):
    """
    Inspector authenticates the metadata and wrapped key package.
    It does not authenticate every encrypted chunk.
    """

    _, encrypted = create_encrypted_file(
        tmp_path, b"Confidential information"
    )

    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)

    info = VaultContainerInspector.inspect(
        encrypted, PASSWORD
    )

    assert info["metadata_authenticated"] is True


def test_wrong_password_after_structural_inspection(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    info = VaultContainerInspector.inspect(encrypted)

    assert info["metadata_authenticated"] is False

    with pytest.raises(ValueError):
        VaultContainerInspector.inspect(
            encrypted, "IncorrectPassword"
        )

def test_invalid_chunk_length_rejected_by_inspector(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"Test chunk validation"
    )

    data = bytearray(encrypted.read_bytes())
    fields = read_header(data)

    chunk_length_offset = (
        VaultFileEngine.BASE_HEADER.size
        + fields[7]
        + SecurityValidator.CONTAINER_WRAPPED_KEY_SIZE
    )

    declared_length = int.from_bytes(
        data[chunk_length_offset:chunk_length_offset + 4],
        "big"
    )

    data[chunk_length_offset:chunk_length_offset + 4] = (
        declared_length + 1
    ).to_bytes(4, "big")

    encrypted.write_bytes(data)

    with pytest.raises(ValueError, match="chunk length"):
        VaultContainerInspector.inspect(encrypted)