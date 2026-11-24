
from pathlib import Path

from PIL import Image

from engine.file_encryption import VaultFileEngine
from engine.steganography import SteganographyEngine


PASSWORD = "StrongVaultPassword!2026"


def test_complete_encryption_steganography_workflow(tmp_path):
    # Step 1: Create an original file.
    original = tmp_path / "original.txt"
    original_data = (
        b"VaultCrypt-512 integration test. "
        b"Testing encryption, steganography and recovery. "
    ) * 100

    original.write_bytes(original_data)

    # Step 2: Create a cover PNG image.
    cover = tmp_path / "cover.png"

    Image.new(
        "RGB",
        (256, 256),
        color=(120, 150, 180)
    ).save(cover)

    # Step 3: Encrypt the original file.
    encrypted = tmp_path / "original.vlt"

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD
    )

    assert encrypted.exists()
    assert encrypted.read_bytes() != original_data

    # Step 4: Hide the encrypted container inside the PNG.
    stego_image = tmp_path / "hidden_vault.png"

    SteganographyEngine.embed_file(
        encrypted,
        cover,
        stego_image
    )

    assert stego_image.exists()

    # Step 5: Extract the hidden encrypted container.
    extracted = tmp_path / "extracted.vlt"

    SteganographyEngine.extract_file(
        stego_image,
        extracted
    )

    assert extracted.exists()
    assert extracted.read_bytes() == encrypted.read_bytes()

    # Step 6: Decrypt the extracted container.
    recovered = tmp_path / "recovered.txt"

    VaultFileEngine.decrypt_file(
        extracted,
        recovered,
        PASSWORD
    )

    # Step 7: Verify byte-for-byte recovery.
    assert recovered.exists()
    assert recovered.read_bytes() == original_data


def test_integration_rejects_wrong_password(tmp_path):
    original = tmp_path / "original.txt"
    original.write_bytes(b"VaultCrypt integration password test")

    encrypted = tmp_path / "original.vlt"

    VaultFileEngine.encrypt_file(
        original,
        encrypted,
        PASSWORD
    )

    cover = tmp_path / "cover.png"

    Image.new(
        "RGB",
        (256, 256),
        color=(100, 120, 140)
    ).save(cover)

    stego_image = tmp_path / "hidden.png"

    SteganographyEngine.embed_file(
        encrypted,
        cover,
        stego_image
    )

    extracted = tmp_path / "extracted.vlt"

    SteganographyEngine.extract_file(
        stego_image,
        extracted
    )

    recovered = tmp_path / "recovered.txt"

    try:
        VaultFileEngine.decrypt_file(
            extracted,
            recovered,
            "WrongPassword"
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Decryption unexpectedly succeeded with the wrong password"
        )

    assert not recovered.exists()
