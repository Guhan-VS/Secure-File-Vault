
import pytest
from engine.security_validator import SecurityValidator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAESGCM

import engine.file_encryption as file_encryption_module
from engine.file_encryption import VaultFileEngine


PASSWORD = "StrongVaultPassword!2026"


def create_encrypted_file(
    tmp_path,
    content=b"Test data",
    chunk_size=None
):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(content)

    if chunk_size is None:
        VaultFileEngine.encrypt_file(
            original, encrypted, PASSWORD
        )
    else:
        VaultFileEngine.encrypt_file(
            original,
            encrypted,
            PASSWORD,
            chunk_size=chunk_size
        )

    return original, encrypted


def get_header_size(data):
    fields = VaultFileEngine.BASE_HEADER.unpack(
        data[:VaultFileEngine.BASE_HEADER.size]
    )

    metadata_length = fields[-1]

    return (
        VaultFileEngine.BASE_HEADER.size
        + metadata_length
        + 32
        + VaultFileEngine.TAG_SIZE
    )


# --------------------------------------------------
# BASIC ENCRYPTION AND DECRYPTION
# --------------------------------------------------

def test_file_encryption_decryption(tmp_path):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"
    recovered = tmp_path / "recovered.txt"

    original.write_bytes(b"VaultCrypt file encryption test")

    VaultFileEngine.encrypt_file(original, encrypted, PASSWORD)
    VaultFileEngine.decrypt_file(encrypted, recovered, PASSWORD)

    assert original.read_bytes() == recovered.read_bytes()


def test_wrong_password(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Secret information"
    )

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, "WrongPassword"
        )

    assert not recovered.exists()


def test_middle_chunk_tampering_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"M" * 3072,
        1024
    )

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    header_size = get_header_size(data)

    first_chunk_record_size = 4 + 1024 + 16
    middle_chunk_offset = (
        header_size
        + first_chunk_record_size
        + 4
    )

    data[middle_chunk_offset + 100] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Chunk 1 authentication failed"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

def test_final_chunk_tampering_leaves_no_plaintext(
    tmp_path
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"F" * 3072,
        1024
    )

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    header_size = get_header_size(data)

    chunk_record_size = 4 + 1024 + 16
    final_chunk_offset = (
        header_size
        + (2 * chunk_record_size)
        + 4
    )

    data[final_chunk_offset + 100] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Chunk 2 authentication failed"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []  

def test_truncated_file(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"B" * 3000, 1024
    )

    recovered = tmp_path / "recovered.txt"

    encrypted.write_bytes(encrypted.read_bytes()[:-1])

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()


def test_chunk_reordering(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"C" * 2500, 1024
    )

    recovered = tmp_path / "recovered.txt"

    data = encrypted.read_bytes()
    header_size = get_header_size(data)

    first_record_size = 4 + 1024 + 16

    first = data[
        header_size:header_size + first_record_size
    ]

    second = data[
        header_size + first_record_size:
        header_size + 2 * first_record_size
    ]

    reordered = (
        data[:header_size]
        + second
        + first
        + data[header_size + 2 * first_record_size:]
    )

    encrypted.write_bytes(reordered)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()



def test_empty_file(tmp_path):
    original, encrypted = create_encrypted_file(
        tmp_path,
        b""
    )

    recovered = tmp_path / "recovered.txt"

    assert original.stat().st_size == 0
    assert encrypted.exists()
    assert encrypted.stat().st_size > 0

    VaultFileEngine.decrypt_file(
        encrypted,
        recovered,
        PASSWORD
    )

    assert recovered.exists()
    assert recovered.read_bytes() == b""
    assert recovered.stat().st_size == 0

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []



def test_large_file(tmp_path):
    original, encrypted = create_encrypted_file(
        tmp_path, b"VAULTCRYPT" * 500000
    )

    recovered = tmp_path / "recovered.bin"

    VaultFileEngine.decrypt_file(
        encrypted, recovered, PASSWORD
    )

    assert original.stat().st_size == recovered.stat().st_size
    assert original.read_bytes() == recovered.read_bytes()


# --------------------------------------------------
# DESTINATION AND INPUT VALIDATION
# --------------------------------------------------

def test_existing_destination_not_overwritten(tmp_path):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(b"Test file")
    encrypted.write_bytes(b"Existing content")

    with pytest.raises(FileExistsError):
        VaultFileEngine.encrypt_file(
            original, encrypted, PASSWORD
        )

    assert encrypted.read_bytes() == b"Existing content"


def test_invalid_chunk_size(tmp_path):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(b"Test file")

    with pytest.raises(ValueError):
        VaultFileEngine.encrypt_file(
            original, encrypted, PASSWORD, chunk_size=100
        )


def test_metadata_preservation(tmp_path):
    original = tmp_path / "confidential_report.pdf"
    encrypted = tmp_path / "report.vlt"
    recovered = tmp_path / "recovered.pdf"

    original.write_bytes(b"PDF test content")

    VaultFileEngine.encrypt_file(original, encrypted, PASSWORD)
    VaultFileEngine.decrypt_file(encrypted, recovered, PASSWORD)

    assert recovered.name == "recovered.pdf"
    assert recovered.read_bytes() == original.read_bytes()


def test_metadata_tampering_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Metadata authentication test"
    )

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    metadata_offset = VaultFileEngine.BASE_HEADER.size
    data[metadata_offset] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()


def test_invalid_vault_magic(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    data[0] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )


def test_unsupported_version(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    data[8] = 99
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )


def test_source_modification_during_encryption_rejected(
    tmp_path,
    monkeypatch
):
    original = tmp_path / "original.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(b"A" * 2048)

    original_read_exact = VaultFileEngine._read_exact
    read_count = 0

    def modify_source_after_first_chunk(cls, file, size):
        nonlocal read_count

        data = original_read_exact(file, size)
        read_count += 1

        if read_count == 1:
            with original.open("r+b") as source_file:
                source_file.seek(0)
                source_file.write(b"Z")

        return data

    monkeypatch.setattr(
        VaultFileEngine,
        "_read_exact",
        classmethod(modify_source_after_first_chunk)
    )

    with pytest.raises(ValueError, match="Source file"):
        VaultFileEngine.encrypt_file(
            original,
            encrypted,
            PASSWORD,
            chunk_size=1024
        )

    assert not encrypted.exists()

def test_source_modification_during_decryption_rejected(
    tmp_path,
    monkeypatch
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"A" * 3072,
        chunk_size=1024
    )

    recovered = tmp_path / "recovered.txt"

    original_decrypt = file_encryption_module.AESGCM.decrypt
    decrypt_count = 0

    def modify_source_after_first_chunk(
        cipher,
        nonce,
        data,
        associated_data
    ):
        nonlocal decrypt_count

        plaintext = original_decrypt(
            cipher,
            nonce,
            data,
            associated_data
        )

        decrypt_count += 1

        if decrypt_count == 1:
            encrypted.touch()

        return plaintext

    monkeypatch.setattr(
        file_encryption_module.AESGCM,
        "decrypt",
        modify_source_after_first_chunk
    )

    with pytest.raises(
        ValueError,
        match="Source container"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []

def test_source_destination_same_path_rejected(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(b"Same path test")

    with pytest.raises(ValueError):
        VaultFileEngine.encrypt_file(
            original,
            original,
            PASSWORD
        )


def test_appended_data_rejected_during_decryption(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Container trailing data test"
    )

    recovered = tmp_path / "recovered.txt"

    with encrypted.open("ab") as file:
        file.write(b"EXTRA")

    with pytest.raises(ValueError, match="trailing"):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()


def test_invalid_chunk_record_length_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path, b"A" * 2048, 1024
    )

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    header_size = get_header_size(data)

    data[header_size:header_size + 4] = (
        (1023).to_bytes(4, "big")
    )

    encrypted.write_bytes(data)

    with pytest.raises(ValueError, match="chunk length"):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()


def test_wrapped_key_tampering_rejected(tmp_path):
    _, encrypted = create_encrypted_file(tmp_path)

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    wrapped_key_offset = (
        VaultFileEngine.BASE_HEADER.size
        + VaultFileEngine.BASE_HEADER.unpack(
            data[:VaultFileEngine.BASE_HEADER.size]
        )[-1]
    )

    data[wrapped_key_offset] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()


def test_failed_decryption_does_not_leave_output_or_temp_file(
    tmp_path
):
    _, encrypted = create_encrypted_file(
        tmp_path, b"Temporary file cleanup test"
    )

    recovered = tmp_path / "recovered.txt"

    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted, recovered, PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []


# ---------------------------------------------------------
# PHASE 5.4.3.1 - NONCE UNIQUENESS AND CHUNK BOUNDARY TESTS
# ---------------------------------------------------------


def test_chunk_nonces_are_unique_within_encryption(
    tmp_path,
    monkeypatch
):
    original = tmp_path / "nonce_test.bin"
    encrypted = tmp_path / "nonce_test.vlt"

    original.write_bytes(b"A" * 4096)

    recorded_nonces = []

    class RecordingAESGCM:
        def __init__(self, key):
            self.cipher = RealAESGCM(key)

        def encrypt(self, nonce, data, associated_data):
            recorded_nonces.append(nonce)

            return self.cipher.encrypt(
                nonce,
                data,
                associated_data
            )

    monkeypatch.setattr(
        file_encryption_module,
        "AESGCM",
        RecordingAESGCM
    )

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD,
        chunk_size=1024
    )

    assert len(recorded_nonces) == 4
    assert len(set(recorded_nonces)) == 4

    for index, nonce in enumerate(recorded_nonces):
        assert len(nonce) == 12
        assert nonce[8:] == index.to_bytes(4, "big")

    assert all(
        nonce[:8] == recorded_nonces[0][:8]
        for nonce in recorded_nonces
    )


def test_separate_encryptions_use_independent_keys_and_nonces(
    tmp_path,
    monkeypatch
):
    original = tmp_path / "independent_test.bin"
    encrypted_one = tmp_path / "first.vlt"
    encrypted_two = tmp_path / "second.vlt"

    original.write_bytes(b"B" * 2048)

    recorded_keys = []
    recorded_nonces = []

    class RecordingAESGCM:
        def __init__(self, key):
            recorded_keys.append(key)
            self.cipher = RealAESGCM(key)

        def encrypt(self, nonce, data, associated_data):
            recorded_nonces.append(nonce)

            return self.cipher.encrypt(
                nonce,
                data,
                associated_data
            )

    monkeypatch.setattr(
        file_encryption_module,
        "AESGCM",
        RecordingAESGCM
    )

    VaultFileEngine.encrypt_file(
        original,
        encrypted_one,
        PASSWORD,
        chunk_size=1024
    )

    first_key = recorded_keys[-1]
    first_nonces = recorded_nonces[-2:]

    VaultFileEngine.encrypt_file(
        original,
        encrypted_two,
        PASSWORD,
        chunk_size=1024
    )

    second_key = recorded_keys[-1]
    second_nonces = recorded_nonces[-2:]

    assert first_key != second_key
    assert set(first_nonces).isdisjoint(set(second_nonces))


@pytest.mark.parametrize(
    "file_size",
    [
        1024,
        2048,
        3072,
        4096
    ]
)
def test_exact_chunk_boundary_encryption_decryption(
    tmp_path,
    file_size
):
    original = tmp_path / "boundary.bin"
    encrypted = tmp_path / "boundary.vlt"
    recovered = tmp_path / "recovered.bin"

    content = b"C" * file_size
    original.write_bytes(content)

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD,
        chunk_size=1024
    )

    VaultFileEngine.decrypt_file(
        encrypted,
        recovered,
        PASSWORD
    )

    assert recovered.read_bytes() == content


@pytest.mark.parametrize(
    "file_size",
    [
        1025,
        2049,
        3073,
        4095
    ]
)
def test_partial_final_chunk_encryption_decryption(
    tmp_path,
    file_size
):
    original = tmp_path / "partial.bin"
    encrypted = tmp_path / "partial.vlt"
    recovered = tmp_path / "recovered.bin"

    content = b"D" * file_size
    original.write_bytes(content)

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD,
        chunk_size=1024
    )

    VaultFileEngine.decrypt_file(
        encrypted, recovered, PASSWORD
    )

    assert recovered.read_bytes() == content


# ---------------------------------------------------------
# PHASE 5.4.3.6 - ENCRYPTED CONTAINER SIZE VALIDATION
# ---------------------------------------------------------

def test_decryption_rejects_container_above_size_limit(
    tmp_path,
    monkeypatch
):

    _, encrypted = create_encrypted_file(tmp_path)

    recovered = tmp_path / "recovered.txt"

    monkeypatch.setattr(
        file_encryption_module.SecurityValidator,
        "MAX_CONTAINER_SIZE",
        10
    )

    with pytest.raises(
        ValueError,
        match="Container exceeds maximum"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()


@pytest.mark.parametrize(
    "metadata_length",
    [
        0,
        VaultFileEngine.MAX_METADATA_SIZE + 1
    ]
)
def test_invalid_metadata_length_rejected_during_decryption(
    tmp_path,
    metadata_length
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"Metadata length validation test"
    )

    data = bytearray(encrypted.read_bytes())

    fields = list(
        VaultFileEngine.BASE_HEADER.unpack(
            data[:VaultFileEngine.BASE_HEADER.size]
        )
    )

    fields[-1] = metadata_length

    data[:VaultFileEngine.BASE_HEADER.size] = (
        VaultFileEngine.BASE_HEADER.pack(*fields)
    )

    encrypted.write_bytes(data)

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(
        ValueError,
        match="Invalid metadata length"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []


def test_invalid_chunk_size_in_header_rejected_during_decryption(
    tmp_path
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"Invalid chunk size test"
    )

    data = bytearray(encrypted.read_bytes())

    fields = list(
        VaultFileEngine.BASE_HEADER.unpack(
            data[:VaultFileEngine.BASE_HEADER.size]
        )
    )

    fields[2] = 100

    data[:VaultFileEngine.BASE_HEADER.size] = (
        VaultFileEngine.BASE_HEADER.pack(*fields)
    )

    encrypted.write_bytes(data)

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(ValueError):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []


def test_oversized_declared_file_size_rejected_during_decryption(
    tmp_path
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"Oversized file size test"
    )

    data = bytearray(encrypted.read_bytes())

    fields = list(
        VaultFileEngine.BASE_HEADER.unpack(
            data[:VaultFileEngine.BASE_HEADER.size]
        )
    )

    fields[3] = SecurityValidator.MAX_FILE_SIZE + 1

    data[:VaultFileEngine.BASE_HEADER.size] = (
        VaultFileEngine.BASE_HEADER.pack(*fields)
    )

    encrypted.write_bytes(data)

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(
        ValueError,
        match="maximum supported size"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []


def test_missing_chunk_length_field_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"A" * 1024,
        1024
    )

    data = encrypted.read_bytes()
    header_size = get_header_size(data)

    # Keep only two bytes of the four-byte chunk-length field.
    encrypted.write_bytes(data[:header_size + 2])

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(
        ValueError,
        match="Truncated or incomplete"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()


def test_truncated_encrypted_chunk_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"B" * 1024,
        1024
    )

    data = encrypted.read_bytes()

    # Remove part of the encrypted chunk and its authentication tag.
    encrypted.write_bytes(data[:-100])

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(
        ValueError,
        match="Truncated or incomplete"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()


def test_incomplete_chunk_authentication_tag_rejected(tmp_path):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"C" * 1024,
        1024
    )

    data = encrypted.read_bytes()

    # Remove eight bytes from the 16-byte authentication tag.
    encrypted.write_bytes(data[:-8])

    recovered = tmp_path / "recovered.txt"

    with pytest.raises(
        ValueError,
        match="Truncated or incomplete"
    ):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()

    temporary_files = list(
        tmp_path.glob(f".{recovered.name}.*.tmp")
    )

    assert temporary_files == []

def test_source_replacement_after_validation_rejected(
    tmp_path,
    monkeypatch
):
    original = tmp_path / "original.txt"
    replacement = tmp_path / "replacement.txt"
    encrypted = tmp_path / "original.vlt"

    original.write_bytes(b"Original content")
    replacement.write_bytes(b"Replacement data")

    original_validate = SecurityValidator.validate_source

    def replace_after_validation(source):
        validated = original_validate(source)

        validated.unlink()
        replacement.replace(validated)

        return validated

    monkeypatch.setattr(
        SecurityValidator,
        "validate_source",
        staticmethod(replace_after_validation)
    )

    with pytest.raises(ValueError, match="replaced"):
        VaultFileEngine.encrypt_file(
            original,
            encrypted,
            PASSWORD
        )

    assert not encrypted.exists()


def test_container_replacement_after_validation_rejected(
    tmp_path,
    monkeypatch
):
    _, encrypted = create_encrypted_file(
        tmp_path,
        b"Original encrypted content"
    )

    replacement = tmp_path / "replacement.vlt"
    replacement.write_bytes(encrypted.read_bytes())

    recovered = tmp_path / "recovered.txt"

    original_validate = SecurityValidator.validate_container_source

    def replace_after_validation(source):
        validated = original_validate(source)

        validated.unlink()
        replacement.replace(validated)

        return validated

    monkeypatch.setattr(
        SecurityValidator,
        "validate_container_source",
        staticmethod(replace_after_validation)
    )

    with pytest.raises(ValueError, match="replaced"):
        VaultFileEngine.decrypt_file(
            encrypted,
            recovered,
            PASSWORD
        )

    assert not recovered.exists()
