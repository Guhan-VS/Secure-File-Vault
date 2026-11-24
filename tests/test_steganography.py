
import pytest
from PIL import Image

from engine.steganography import (
    SteganographyEngine,
    SteganographyError,
)


@pytest.fixture
def cover_image(tmp_path):
    path = tmp_path / "cover.png"

    Image.new(
        "RGB",
        (256, 256),
        color=(120, 150, 180)
    ).save(path)

    return path


@pytest.fixture
def encrypted_file(tmp_path):
    path = tmp_path / "sample.vlt"
    path.write_bytes(
        b"VLT-TEST-DATA-" * 100
    )
    return path


def test_embed_and_extract_file(
    tmp_path,
    cover_image,
    encrypted_file
):
    encoded = tmp_path / "encoded.png"
    extracted = tmp_path / "extracted.vlt"

    SteganographyEngine.embed_file(
        encrypted_file,
        cover_image,
        encoded
    )

    SteganographyEngine.extract_file(
        encoded,
        extracted
    )

    assert extracted.read_bytes() == encrypted_file.read_bytes()


def test_image_capacity(cover_image):
    capacity = SteganographyEngine.get_capacity(
        cover_image
    )

    assert capacity > 0


def test_insufficient_capacity(
    tmp_path,
    encrypted_file
):
    tiny_image = tmp_path / "tiny.png"

    Image.new(
        "RGB",
        (8, 8),
        color=(100, 100, 100)
    ).save(tiny_image)

    output = tmp_path / "output.png"

    with pytest.raises(
        SteganographyError,
        match="capacity"
    ):
        SteganographyEngine.embed_file(
            encrypted_file,
            tiny_image,
            output
        )

    assert not output.exists()


def test_non_vlt_file_rejected(
    tmp_path,
    cover_image
):
    invalid_file = tmp_path / "sample.txt"
    invalid_file.write_text("Not encrypted")

    with pytest.raises(
        SteganographyError,
        match="encrypted"
    ):
        SteganographyEngine.embed_file(
            invalid_file,
            cover_image,
            tmp_path / "output.png"
        )


def test_non_png_cover_rejected(
    tmp_path,
    encrypted_file
):
    jpg = tmp_path / "cover.jpg"

    Image.new(
        "RGB",
        (256, 256)
    ).save(jpg)

    with pytest.raises(
        SteganographyError,
        match="PNG"
    ):
        SteganographyEngine.embed_file(
            encrypted_file,
            jpg,
            tmp_path / "output.png"
        )


def test_existing_output_not_overwritten(
    tmp_path,
    cover_image,
    encrypted_file
):
    output = tmp_path / "existing.png"
    original_data = b"Do not overwrite"

    output.write_bytes(original_data)

    with pytest.raises(
        SteganographyError,
        match="already exists"
    ):
        SteganographyEngine.embed_file(
            encrypted_file,
            cover_image,
            output
        )

    assert output.read_bytes() == original_data


def test_image_without_payload_rejected(
    tmp_path,
    cover_image
):
    output = tmp_path / "extracted.vlt"

    with pytest.raises(
        SteganographyError,
        match="No valid"
    ):
        SteganographyEngine.extract_file(
            cover_image,
            output
        )

    assert not output.exists()


def test_corrupted_payload_detected(
    tmp_path,
    cover_image,
    encrypted_file
):
    encoded = tmp_path / "encoded.png"
    extracted = tmp_path / "extracted.vlt"

    SteganographyEngine.embed_file(
        encrypted_file,
        cover_image,
        encoded
    )

    with Image.open(encoded) as source:
        image = source.convert("RGB")

    pixels = bytearray(image.tobytes())

    # Flip one embedded payload bit after the header.
    payload_start = (
        SteganographyEngine.HEADER_SIZE * 8
    )
    pixels[payload_start] ^= 1

    corrupted = Image.frombytes(
        "RGB",
        image.size,
        bytes(pixels)
    )

    corrupted.save(encoded)

    with pytest.raises(
        SteganographyError,
        match="integrity"
    ):
        SteganographyEngine.extract_file(
            encoded,
            extracted
        )

    assert not extracted.exists()


def test_header_tampering_detected(
    tmp_path,
    cover_image,
    encrypted_file
):
    encoded = tmp_path / "encoded.png"
    extracted = tmp_path / "extracted.vlt"

    SteganographyEngine.embed_file(
        encrypted_file,
        cover_image,
        encoded
    )

    with Image.open(encoded) as source:
        image = source.convert("RGB")

    pixels = bytearray(image.tobytes())

    # Modify a bit in the embedded header.
    pixels[SteganographyEngine.HEADER_SIZE * 8 - 1] ^= 1

    Image.frombytes(
        "RGB",
        image.size,
        bytes(pixels)
    ).save(encoded)

    with pytest.raises(
        SteganographyError,
        match="header integrity"
    ):
        SteganographyEngine.extract_file(
            encoded,
            extracted
        )

    assert not extracted.exists()


def test_oversized_payload_rejected(
    tmp_path,
    cover_image
):
    payload = tmp_path / "large.vlt"

    with payload.open("wb") as file:
        file.truncate(
            SteganographyEngine.MAX_PAYLOAD_SIZE + 1
        )

    with pytest.raises(
        SteganographyError,
        match="maximum size"
    ):
        SteganographyEngine.embed_file(
            payload,
            cover_image,
            tmp_path / "output.png"
        )


def test_oversized_image_rejected(
    tmp_path,
    monkeypatch
):
    image_path = tmp_path / "large.png"

    monkeypatch.setattr(
        SteganographyEngine,
        "MAX_IMAGE_PIXELS",
        100
    )

    Image.new("RGB", (20, 20)).save(image_path)

    with pytest.raises(
        SteganographyError,
        match="maximum pixel"
    ):
        SteganographyEngine.get_capacity(image_path)


def test_failed_atomic_write_leaves_no_temp_file(
    tmp_path
):
    output = tmp_path / "result.vlt"

    def failing_writer(file):
        file.write(b"partial data")
        raise OSError("Simulated write failure")

    with pytest.raises(
        SteganographyError,
        match="publish output"
    ):
        SteganographyEngine._atomic_write(
            output,
            failing_writer
        )

    assert not output.exists()

    temporary_files = list(
        tmp_path.glob(".vaultcrypt-*.tmp")
    )

    assert temporary_files == []
