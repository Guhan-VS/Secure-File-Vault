
import pytest

from engine.file_encryption import VaultFileEngine
from engine.file_recovery import VaultFileRecovery
from engine.container_inspector import VaultContainerInspector
from engine.security_validator import SecurityValidator


PASSWORD = "StrongVaultPassword!2026"


# --------------------------------------------------
# BASIC FILE RECOVERY
# --------------------------------------------------

def test_automatic_filename_recovery(tmp_path):
    source = tmp_path / "confidential_report.pdf"
    encrypted = tmp_path / "report.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Confidential PDF content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    recovered = VaultFileRecovery.recover_file(
        encrypted, recovery_dir, PASSWORD
    )

    assert recovered.name == "confidential_report.pdf"
    assert recovered.read_bytes() == source.read_bytes()


def test_original_extension_preserved(tmp_path):
    source = tmp_path / "document.docx"
    encrypted = tmp_path / "document.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Document content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    recovered = VaultFileRecovery.recover_file(
        encrypted, recovery_dir, PASSWORD
    )

    assert recovered.suffix == ".docx"


def test_filename_collision_renamed(tmp_path):
    source = tmp_path / "report.pdf"
    encrypted = tmp_path / "report.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Original content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    existing = recovery_dir / "report.pdf"
    existing.write_bytes(b"Existing content")

    recovered = VaultFileRecovery.recover_file(
        encrypted, recovery_dir, PASSWORD
    )

    assert recovered.name == "report (1).pdf"
    assert existing.read_bytes() == b"Existing content"
    assert recovered.read_bytes() == source.read_bytes()


# --------------------------------------------------
# PASSWORD AND PATH VALIDATION
# --------------------------------------------------

def test_wrong_password_rejected(tmp_path):
    source = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Secret content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    with pytest.raises(ValueError):
        VaultFileRecovery.recover_file(
            encrypted, recovery_dir, "WrongPassword"
        )

    assert list(recovery_dir.iterdir()) == []


def test_missing_container_rejected(tmp_path):
    recovery_dir = tmp_path / "recovered"
    recovery_dir.mkdir()

    with pytest.raises(FileNotFoundError):
        VaultFileRecovery.recover_file(
            tmp_path / "missing.vlt",
            recovery_dir,
            PASSWORD
        )


def test_missing_destination_directory_rejected(tmp_path):
    source = tmp_path / "file.txt"
    encrypted = tmp_path / "file.vlt"

    source.write_bytes(b"Test content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    with pytest.raises(NotADirectoryError):
        VaultFileRecovery.recover_file(
            encrypted,
            tmp_path / "missing",
            PASSWORD
        )


# --------------------------------------------------
# METADATA AND CONTENT VALIDATION
# --------------------------------------------------

def test_metadata_tampering_rejected(tmp_path):
    source = tmp_path / "report.pdf"
    encrypted = tmp_path / "report.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Metadata security test")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    data = bytearray(encrypted.read_bytes())
    metadata_offset = VaultFileEngine.BASE_HEADER.size
    data[metadata_offset] ^= 1

    encrypted.write_bytes(data)

    with pytest.raises(ValueError):
        VaultFileRecovery.recover_file(
            encrypted, recovery_dir, PASSWORD
        )

    assert list(recovery_dir.iterdir()) == []


def test_empty_file_recovery(tmp_path):
    source = tmp_path / "empty.txt"
    encrypted = tmp_path / "empty.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    recovered = VaultFileRecovery.recover_file(
        encrypted, recovery_dir, PASSWORD
    )

    assert recovered.name == "empty.txt"
    assert recovered.read_bytes() == b""


def test_invalid_recovery_filename_rejected():
    invalid_names = [
        "../secret.txt",
        "folder\\secret.txt",
        "CON.txt",
        "invalid:name.txt",
        "trailing.",
    ]

    for filename in invalid_names:
        with pytest.raises(ValueError):
            VaultFileRecovery._validate_filename(filename)


# --------------------------------------------------
# SNAPSHOT INTEGRITY TESTS
# --------------------------------------------------

def test_snapshot_rejects_container_growth(tmp_path, monkeypatch):
    source = tmp_path / "container.vlt"
    source.write_bytes(b"Original container")

    original_signature = VaultFileEngine._file_signature
    calls = 0

    def signature_with_growth(stat_result):
        nonlocal calls

        result = original_signature(stat_result)
        calls += 1

        if calls == 1:
            with source.open("ab") as file:
                file.write(b"ADDED")

        return result

    monkeypatch.setattr(
        VaultFileEngine,
        "_file_signature",
        signature_with_growth
    )

    with pytest.raises(ValueError, match="grew"):
        VaultFileRecovery._create_container_snapshot(
            source, tmp_path
        )

    assert not list(
        tmp_path.glob(".vaultcrypt-recovery-*.tmp")
    )


def test_snapshot_rejects_container_truncation(tmp_path, monkeypatch):
    source = tmp_path / "container.vlt"
    source.write_bytes(b"Original container content")

    original_signature = VaultFileEngine._file_signature
    calls = 0

    def signature_with_truncation(stat_result):
        nonlocal calls

        result = original_signature(stat_result)
        calls += 1

        if calls == 1:
            source.write_bytes(b"Short")

        return result

    monkeypatch.setattr(
        VaultFileEngine,
        "_file_signature",
        signature_with_truncation
    )

    with pytest.raises(ValueError, match="truncated"):
        VaultFileRecovery._create_container_snapshot(
            source, tmp_path
        )

    assert not list(
        tmp_path.glob(".vaultcrypt-recovery-*.tmp")
    )


def test_snapshot_rejects_path_replacement(tmp_path, monkeypatch):
    source = tmp_path / "container.vlt"
    source.write_bytes(b"Original container content")

    original_path_signature = VaultFileEngine._path_signature
    calls = 0

    def signature_with_replacement(stat_result):
        nonlocal calls

        result = original_path_signature(stat_result)
        calls += 1

        # Simulate the path referring to a different file
        # during the final path-signature verification.
        # No actual deletion or replacement is attempted.
        if calls == 2:
            return result + ("replacement",)

        return result

    monkeypatch.setattr(
        VaultFileEngine,
        "_path_signature",
        signature_with_replacement
    )

    with pytest.raises(ValueError, match="replaced"):
        VaultFileRecovery._create_container_snapshot(
            source, tmp_path
        )

    assert not list(
        tmp_path.glob(".vaultcrypt-recovery-*.tmp")
    )


# --------------------------------------------------
# SYMLINK AND SIZE VALIDATION
# --------------------------------------------------

def test_snapshot_rejects_symlink(tmp_path):
    source = tmp_path / "real_container.vlt"
    link = tmp_path / "linked_container.vlt"

    source.write_bytes(b"Container data")

    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable")

    with pytest.raises(ValueError, match="Symbolic link"):
        VaultFileRecovery._create_container_snapshot(
            link, tmp_path
        )


def test_snapshot_rejects_oversized_container(
    tmp_path,
    monkeypatch
):
    source = tmp_path / "large_container.vlt"
    source.write_bytes(b"123456789")

    monkeypatch.setattr(
        SecurityValidator,
        "MAX_CONTAINER_SIZE",
        8
    )

    with pytest.raises(
        ValueError,
        match="maximum supported size"
    ):
        VaultFileRecovery._create_container_snapshot(
            source, tmp_path
        )

    assert not list(
        tmp_path.glob(".vaultcrypt-recovery-*.tmp")
    )


# --------------------------------------------------
# TEMPORARY FILE CLEANUP
# --------------------------------------------------

def test_snapshot_cleanup_when_inspection_fails(
    tmp_path,
    monkeypatch
):
    source = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.vlt"
    recovery_dir = tmp_path / "recovered"

    recovery_dir.mkdir()
    source.write_bytes(b"Cleanup test content")

    VaultFileEngine.encrypt_file(source, encrypted, PASSWORD)

    def fail_inspection(*args, **kwargs):
        raise ValueError("Simulated inspection failure")

    monkeypatch.setattr(
        VaultContainerInspector,
        "inspect",
        fail_inspection
    )

    with pytest.raises(
        ValueError,
        match="Simulated inspection failure"
    ):
        VaultFileRecovery.recover_file(
            encrypted, recovery_dir, PASSWORD
        )

    assert not list(
        recovery_dir.glob(".vaultcrypt-recovery-*.tmp")
    )

    assert list(recovery_dir.iterdir()) == []


# --------------------------------------------------
# WINDOWS RESERVED FILENAME VALIDATION
# --------------------------------------------------

@pytest.mark.parametrize(
    "filename",
    [
        "CONIN$",
        "CONOUT$",
        "CONIN$.txt",
        "CONOUT$.log",
        "COM¹.txt",
        "COM².txt",
        "COM³.txt",
        "LPT¹.txt",
        "LPT².txt",
        "LPT³.txt",
        "CON .txt",
        "NUL .txt",
        "conin$",
        "com¹.data",
    ]
)
def test_windows_reserved_names_rejected(filename):
    with pytest.raises(
        ValueError,
        match="Reserved Windows filename"
    ):
        VaultFileRecovery._validate_filename(filename)


def test_unicode_filename_utf16_length_limit():
    valid_filename = "😀" * 127
    invalid_filename = "😀" * 128

    assert (
        VaultFileRecovery._validate_filename(valid_filename)
        == valid_filename
    )

    with pytest.raises(ValueError, match="too long"):
        VaultFileRecovery._validate_filename(invalid_filename)


def test_unpaired_unicode_surrogate_rejected():
    invalid_filename = "report_\ud800.txt"

    with pytest.raises(ValueError, match="Invalid Unicode"):
        VaultFileRecovery._validate_filename(invalid_filename)
