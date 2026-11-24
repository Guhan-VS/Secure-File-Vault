
import os

import pytest

from engine.file_encryption import VaultFileEngine


@pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
def test_fsync_failure_preserves_error_and_cleans_output(
    tmp_path,
    monkeypatch,
    operation,
):
    password = "TestPassword-512!"
    chunk_size = 1024

    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.vlt"
    destination = tmp_path / "restored.bin"

    source.write_bytes(b"A" * 4096)

    if operation == "decrypt":
        VaultFileEngine.encrypt_file(
            source,
            encrypted,
            password,
            chunk_size=chunk_size,
        )
        input_path = encrypted
    else:
        input_path = source

    original_error = RuntimeError(
        "Simulated filesystem synchronization failure"
    )

    fsync_calls = []

    def failing_fsync(fd):
        fsync_calls.append(fd)
        raise original_error

    monkeypatch.setattr(
        "engine.file_encryption.os.fsync",
        failing_fsync,
    )

    with pytest.raises(RuntimeError) as exc_info:
        if operation == "encrypt":
            VaultFileEngine.encrypt_file(
                input_path,
                destination,
                password,
                chunk_size=chunk_size,
            )
        else:
            VaultFileEngine.decrypt_file(
                input_path,
                destination,
                password,
            )

    assert exc_info.value is original_error
    assert len(fsync_calls) == 1
    assert not destination.exists()

    temporary_files = list(
        tmp_path.glob(f".{destination.name}.*.tmp")
    )

    assert temporary_files == []


@pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
def test_output_is_fsynced_before_destination_is_published(
    tmp_path,
    monkeypatch,
    operation,
):
    password = "TestPassword-512!"
    chunk_size = 1024

    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.vlt"
    destination = tmp_path / "restored.bin"

    source.write_bytes(b"B" * 4096)

    if operation == "decrypt":
        VaultFileEngine.encrypt_file(
            source,
            encrypted,
            password,
            chunk_size=chunk_size,
        )
        input_path = encrypted
    else:
        input_path = source

    original_fsync = os.fsync
    fsync_calls = []

    def checking_fsync(fd):
        fsync_calls.append(fd)

        # The final destination must not exist yet.
        assert not destination.exists()

        # The temporary output must still exist.
        temporary_files = list(
            tmp_path.glob(f".{destination.name}.*.tmp")
        )

        assert len(temporary_files) == 1

        # Perform the real filesystem synchronization.
        return original_fsync(fd)

    monkeypatch.setattr(
        "engine.file_encryption.os.fsync",
        checking_fsync,
    )

    if operation == "encrypt":
        VaultFileEngine.encrypt_file(
            input_path,
            destination,
            password,
            chunk_size=chunk_size,
        )
    else:
        VaultFileEngine.decrypt_file(
            input_path,
            destination,
            password,
        )

    assert len(fsync_calls) == 1
    assert destination.exists()

    # Temporary output must be removed after finalization.
    temporary_files = list(
        tmp_path.glob(f".{destination.name}.*.tmp")
    )

    assert temporary_files == []
