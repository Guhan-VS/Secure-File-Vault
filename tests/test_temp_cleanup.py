
from pathlib import Path
import os
import stat
import pytest

from engine.file_encryption import VaultFileEngine


def test_cleanup_does_not_close_transferred_descriptor(
    tmp_path,
    monkeypatch
):
    """
    When fd ownership has transferred to a file object,
    cleanup must not attempt to close it again.
    """

    temp_file = tmp_path / "temporary.tmp"
    temp_file.write_bytes(b"temporary data")

    close_calls = []

    def unexpected_close(fd):
        close_calls.append(fd)
        raise AssertionError(
            "Transferred descriptor must not be closed again"
        )

    monkeypatch.setattr(
        "engine.file_encryption.os.close",
        unexpected_close
    )

    original_error = ValueError("Original encryption error")

    VaultFileEngine._cleanup_failed_output(
        None,
        temp_file,
        original_error
    )

    assert close_calls == []
    assert not temp_file.exists()


def test_cleanup_failure_preserves_original_exception(
    tmp_path,
    monkeypatch
):
    """
    A temporary-file deletion failure must not replace
    the original encryption/decryption exception.
    """

    temp_file = tmp_path / "temporary.tmp"
    temp_file.write_bytes(b"temporary data")

    original_error = ValueError("Original encryption error")

    def fail_unlink(self, *args, **kwargs):
        raise PermissionError("Simulated deletion failure")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    VaultFileEngine._cleanup_failed_output(
        None,
        temp_file,
        original_error
    )

    assert str(original_error) == "Original encryption error"

    notes = getattr(original_error, "__notes__", [])

    assert any(
        "Temporary file cleanup failed" in note
        and "Simulated deletion failure" in note
        for note in notes
    )


@pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
def test_workflow_does_not_double_close_transferred_descriptor(
    tmp_path,
    monkeypatch,
    operation
):
    password = "CorrectHorseBatteryStaple!2026"

    source = tmp_path / "source.txt"
    source.write_bytes(b"VaultCrypt descriptor ownership test")

    encrypted = tmp_path / "source.vlt"

    if operation == "decrypt":
        VaultFileEngine.encrypt_file(
            source,
            encrypted,
            password
        )

    real_fdopen = __import__("os").fdopen
    close_calls = []

    class FailingOutput:
        def __init__(self, file_object):
            self.file_object = file_object

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.file_object.close()
            return False

        def write(self, data):
            raise OSError("Simulated output write failure")

    def tracked_fdopen(fd, *args, **kwargs):
        return FailingOutput(real_fdopen(fd, *args, **kwargs))

    import os

    real_close = os.close

    def tracked_close(fd):
        close_calls.append(fd)
        return real_close(fd)

    monkeypatch.setattr(
        "engine.file_encryption.os.fdopen",
        tracked_fdopen
    )

    monkeypatch.setattr(
        "engine.file_encryption.os.close",
        tracked_close
    )

    destination = tmp_path / (
        "decrypted.txt" if operation == "decrypt"
        else "encrypted.vlt"
    )

    input_path = encrypted if operation == "decrypt" else source

    with pytest.raises(
        OSError,
        match="Simulated output write failure"
    ):
        if operation == "decrypt":
            VaultFileEngine.decrypt_file(
                input_path,
                destination,
                password
            )
        else:
            VaultFileEngine.encrypt_file(
                input_path,
                destination,
                password
            )

    assert close_calls == []
    assert not destination.exists()
    assert list(tmp_path.glob(f".{destination.name}.*.tmp")) == []


def test_finalize_output_rolls_back_destination_if_temp_unlink_fails(
    tmp_path,
    monkeypatch
):
    temp_file = tmp_path / ".vault.tmp"
    destination = tmp_path / "vault.vlt"

    temp_file.write_bytes(b"encrypted vault data")

    real_unlink = __import__("os").unlink
    unlink_calls = []

    def fail_first_unlink(path, *args, **kwargs):
        unlink_calls.append(path)

        if len(unlink_calls) == 1:
            raise PermissionError(
                "Simulated temporary-file deletion failure"
            )

        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        "engine.file_encryption.os.unlink",
        fail_first_unlink
    )

    with pytest.raises(
        PermissionError,
        match="Simulated temporary-file deletion failure"
    ):
        VaultFileEngine._finalize_output(
            temp_file,
            destination
        )

    # Destination must be rolled back.
    assert not destination.exists()

    # Original temporary file must remain intact.
    assert temp_file.exists()
    assert temp_file.read_bytes() == b"encrypted vault data"


def test_finalize_output_preserves_original_error_if_rollback_fails(
    tmp_path,
    monkeypatch
):
    temp_file = tmp_path / ".vault.tmp"
    destination = tmp_path / "vault.vlt"

    temp_file.write_bytes(b"encrypted vault data")

    real_unlink = __import__("os").unlink
    unlink_calls = []

    def fail_both_unlinks(path, *args, **kwargs):
        unlink_calls.append(path)

        if len(unlink_calls) <= 2:
            raise PermissionError(
                f"Simulated deletion failure {len(unlink_calls)}"
            )

        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        "engine.file_encryption.os.unlink",
        fail_both_unlinks
    )

    with pytest.raises(
        PermissionError,
        match="Simulated deletion failure 1"
    ) as exc_info:

        VaultFileEngine._finalize_output(
            temp_file,
            destination
        )

    # Both filenames remain because both deletion attempts failed.
    assert temp_file.exists()
    assert destination.exists()

    # Both filenames still refer to the same file.
    assert temp_file.stat().st_ino == destination.stat().st_ino

    # The original error must be preserved.
    assert "Simulated deletion failure 1" in str(exc_info.value)

    # The rollback failure must be recorded as an exception note.
    assert any(
        "Destination rollback failed" in note
        for note in exc_info.value.__notes__
    )

    assert len(unlink_calls) == 2


def test_finalize_output_does_not_overwrite_destination_created_during_race(
    tmp_path,
    monkeypatch
):
    temp_file = tmp_path / ".vault.tmp"
    destination = tmp_path / "vault.vlt"

    temp_file.write_bytes(b"Our encrypted vault data")

    real_link = __import__("os").link
    link_calls = []

    def create_competing_destination(source, target, *args, **kwargs):
        link_calls.append((source, target))

        # Simulate another process creating the destination
        # after our initial existence check.
        destination.write_bytes(b"Another process's data")

        # Attempt the original atomic hard-link operation.
        return real_link(source, target, *args, **kwargs)

    monkeypatch.setattr(
        "engine.file_encryption.os.link",
        create_competing_destination
    )

    with pytest.raises(FileExistsError):
        VaultFileEngine._finalize_output(
            temp_file,
            destination
        )

    # The competing process's file must remain untouched.
    assert destination.exists()
    assert destination.read_bytes() == b"Another process's data"

    # Our temporary file must remain available for cleanup.
    assert temp_file.exists()
    assert temp_file.read_bytes() == b"Our encrypted vault data"

    assert len(link_calls) == 1


def test_two_operations_cannot_overwrite_same_destination(tmp_path):
    temp_file_a = tmp_path / ".vault_a.tmp"
    temp_file_b = tmp_path / ".vault_b.tmp"
    destination = tmp_path / "vault.vlt"

    temp_file_a.write_bytes(b"First operation data")
    temp_file_b.write_bytes(b"Second operation data")

    # First operation wins.
    VaultFileEngine._finalize_output(
        temp_file_a,
        destination
    )

    # Second operation must not overwrite the destination.
    with pytest.raises(FileExistsError):
        VaultFileEngine._finalize_output(
            temp_file_b,
            destination
        )

    assert destination.exists()
    assert destination.read_bytes() == b"First operation data"

    assert not temp_file_a.exists()

    assert temp_file_b.exists()
    assert temp_file_b.read_bytes() == b"Second operation data"


def test_finalize_output_rejects_symbolic_link_destination(tmp_path):
    target_file = tmp_path / "original.txt"
    destination = tmp_path / "vault.vlt"
    temp_file = tmp_path / ".vault.tmp"

    target_file.write_bytes(b"Original protected data")
    temp_file.write_bytes(b"New encrypted data")

    # Windows may require Developer Mode or administrator
    # privileges to create symbolic links.
    try:
        destination.symlink_to(target_file)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Symbolic links are unavailable: {error}")

    with pytest.raises(FileExistsError):
        VaultFileEngine._finalize_output(
            temp_file,
            destination
        )

    # The symbolic link must still point to the original file.
    assert destination.is_symlink()
    assert destination.resolve() == target_file.resolve()

    # The target must not be modified.
    assert target_file.read_bytes() == b"Original protected data"

    # The temporary file must remain available for cleanup.
    assert temp_file.exists()
    assert temp_file.read_bytes() == b"New encrypted data"


def test_create_output_uses_restrictive_temporary_file_permissions(
    tmp_path
):
    destination = tmp_path / "vault.vlt"

    _, fd, temp_path = VaultFileEngine._create_output(destination)

    try:
        os.close(fd)

        permissions = stat.S_IMODE(
            os.stat(temp_path).st_mode
        )

        if os.name == "nt":
            # Windows does not expose its full NTFS ACL through
            # stat.S_IMODE. Do not treat this as an ACL security test.
            assert stat.S_ISREG(os.stat(temp_path).st_mode)
        else:
            assert permissions & 0o077 == 0

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_encrypt_file_cleans_partial_output_after_encryption_failure(
    tmp_path,
    monkeypatch
):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    source = tmp_path / "secret.txt"
    destination = tmp_path / "secret.vlt"

    # Ensure multiple chunks are available for encryption.
    source.write_bytes(b"A" * 4096)

    original_error = RuntimeError(
        "Simulated encryption interruption"
    )

    original_encrypt = AESGCM.encrypt
    calls = 0

    def fail_during_encryption(self, nonce, data, associated_data):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise original_error

        return original_encrypt(
            self,
            nonce,
            data,
            associated_data
        )

    monkeypatch.setattr(
        AESGCM,
        "encrypt",
        fail_during_encryption
    )

    with pytest.raises(RuntimeError) as exc_info:
        VaultFileEngine.encrypt_file(
            source,
            destination,
            "TestPassword123!"
        )

    assert exc_info.value is original_error
    assert calls == 2
    assert not destination.exists()

    temporary_files = list(
        tmp_path.glob(f".{destination.name}.*.tmp")
    )

    assert temporary_files == []
