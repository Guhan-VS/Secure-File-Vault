
import hashlib
import hmac
import os
import struct
import tempfile
from pathlib import Path

from PIL import Image, UnidentifiedImageError


class SteganographyError(Exception):
    """Raised when embedding or extracting hidden data fails."""


class SteganographyEngine:
    """
    Hide and extract encrypted VaultCrypt containers using PNG LSB encoding.
    """

    MAGIC = b"VCRYPT01"
    HEADER_FORMAT = ">8sQ32s32s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    MAX_IMAGE_PIXELS = 40_000_000
    MAX_PAYLOAD_SIZE = 64 * 1024 * 1024

    @classmethod
    def _load_png(cls, image_path):
        image_path = Path(image_path)

        if not image_path.is_file():
            raise SteganographyError("Cover image does not exist")

        try:
            with Image.open(image_path) as source:
                if source.format != "PNG":
                    raise SteganographyError(
                        "Only PNG images are supported"
                    )

                width, height = source.size

                if width <= 0 or height <= 0:
                    raise SteganographyError("Invalid image dimensions")

                if width * height > cls.MAX_IMAGE_PIXELS:
                    raise SteganographyError(
                        "Image exceeds the maximum pixel limit"
                    )

                source.load()
                return source.convert("RGB")

        except SteganographyError:
            raise
        except (OSError, ValueError, UnidentifiedImageError) as exc:
            raise SteganographyError(
                "Unable to read PNG image"
            ) from exc

    @classmethod
    def get_capacity(cls, image_path):
        """Return maximum supported payload capacity in bytes."""
        image = cls._load_png(image_path)

        total_channels = image.width * image.height * 3
        total_bytes = total_channels // 8

        capacity = max(0, total_bytes - cls.HEADER_SIZE)

        return min(capacity, cls.MAX_PAYLOAD_SIZE)

    @staticmethod
    def _bytes_to_bits(data):
        for byte in data:
            for shift in range(7, -1, -1):
                yield (byte >> shift) & 1

    @staticmethod
    def _bits_to_bytes(image_data, bit_count):
        if bit_count < 0 or bit_count % 8:
            raise SteganographyError("Invalid payload bit length")

        if bit_count > len(image_data):
            raise SteganographyError("Payload exceeds image capacity")

        output = bytearray()

        for start in range(0, bit_count, 8):
            value = 0

            for offset in range(8):
                value <<= 1
                value |= image_data[start + offset] & 1

            output.append(value)

        return bytes(output)

    @classmethod
    def _header_checksum(cls, magic, length, digest):
        """Detect accidental corruption of header fields."""
        metadata = struct.pack(">8sQ32s", magic, length, digest)
        return hashlib.sha256(metadata).digest()

    @staticmethod
    def _atomic_write(output_path, writer):
        """Write to a temporary file and publish without overwriting."""
        output_path = Path(output_path)
        temporary_path = None

        if not output_path.parent.is_dir():
            raise SteganographyError(
                "Output directory does not exist"
            )

        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".vaultcrypt-",
                suffix=".tmp",
                dir=output_path.parent,
            )

            temporary_path = Path(temporary_name)

            with os.fdopen(descriptor, "wb") as temporary_file:
                writer(temporary_file)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            # Atomic publication; fails if destination already exists.
            os.link(temporary_path, output_path)

            return output_path

        except FileExistsError as exc:
            raise SteganographyError(
                "Output file already exists"
            ) from exc

        except SteganographyError:
            raise

        except OSError as exc:
            raise SteganographyError(
                "Unable to publish output file"
            ) from exc

        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass

    @classmethod
    def embed_file(cls, input_file, cover_image, output_image):
        """Embed an encrypted .vlt file inside a PNG image."""
        input_file = Path(input_file)
        output_image = Path(output_image)

        if not input_file.is_file():
            raise SteganographyError("Input file does not exist")

        if input_file.suffix.lower() != ".vlt":
            raise SteganographyError(
                "Only encrypted .vlt containers are accepted"
            )

        if output_image.suffix.lower() != ".png":
            raise SteganographyError(
                "Output image must have a .png extension"
            )

        if output_image.exists():
            raise SteganographyError(
                "Output image already exists"
            )

        if input_file.resolve() == output_image.resolve():
            raise SteganographyError(
                "Input and output paths must be different"
            )

        try:
            declared_size = input_file.stat().st_size

            if declared_size > cls.MAX_PAYLOAD_SIZE:
                raise SteganographyError(
                    "Payload exceeds the maximum size limit"
                )

            image = cls._load_png(cover_image)

            total_channels = image.width * image.height * 3
            capacity = max(
                0,
                total_channels // 8 - cls.HEADER_SIZE
            )
            capacity = min(capacity, cls.MAX_PAYLOAD_SIZE)

            if declared_size > capacity:
                raise SteganographyError(
                    "Image does not have enough capacity"
                )

            payload = input_file.read_bytes()

        except SteganographyError:
            raise
        except OSError as exc:
            raise SteganographyError(
                "Unable to read input file"
            ) from exc

        if len(payload) != declared_size:
            raise SteganographyError(
                "Input file changed while being read"
            )

        digest = hashlib.sha256(payload).digest()

        checksum = cls._header_checksum(
            cls.MAGIC,
            len(payload),
            digest,
        )

        header = struct.pack(
            cls.HEADER_FORMAT,
            cls.MAGIC,
            len(payload),
            digest,
            checksum,
        )

        encoded_data = header + payload
        pixels = bytearray(image.tobytes())

        required_bits = len(encoded_data) * 8

        if required_bits > len(pixels):
            raise SteganographyError(
                "Image does not have enough capacity"
            )

        for index, bit in enumerate(
            cls._bytes_to_bits(encoded_data)
        ):
            pixels[index] = (pixels[index] & 0xFE) | bit

        encoded_image = Image.frombytes(
            "RGB",
            image.size,
            bytes(pixels),
        )

        def save_image(output):
            encoded_image.save(output, format="PNG")

        return cls._atomic_write(output_image, save_image)

    @classmethod
    def extract_file(cls, stego_image, output_file):
        """Extract and validate a hidden encrypted .vlt file."""
        output_file = Path(output_file)

        if output_file.suffix.lower() != ".vlt":
            raise SteganographyError(
                "Extracted output must have a .vlt extension"
            )

        if output_file.exists():
            raise SteganographyError(
                "Output file already exists"
            )

        image = cls._load_png(stego_image)
        pixels = image.tobytes()

        header_bits = cls.HEADER_SIZE * 8

        if header_bits > len(pixels):
            raise SteganographyError(
                "Image is too small to contain a payload"
            )

        header = cls._bits_to_bytes(
            pixels,
            header_bits,
        )

        try:
            (
                magic,
                payload_length,
                expected_digest,
                expected_checksum,
            ) = struct.unpack(cls.HEADER_FORMAT, header)

        except struct.error as exc:
            raise SteganographyError(
                "Invalid hidden data header"
            ) from exc

        if magic != cls.MAGIC:
            raise SteganographyError(
                "No valid VaultCrypt payload found"
            )

        if payload_length > cls.MAX_PAYLOAD_SIZE:
            raise SteganographyError(
                "Hidden payload exceeds the maximum size limit"
            )

        actual_checksum = cls._header_checksum(
            magic,
            payload_length,
            expected_digest,
        )

        if not hmac.compare_digest(
            expected_checksum,
            actual_checksum,
        ):
            raise SteganographyError(
                "Hidden payload header integrity check failed"
            )

        total_bits = (cls.HEADER_SIZE + payload_length) * 8

        if total_bits > len(pixels):
            raise SteganographyError(
                "Hidden payload is truncated or invalid"
            )

        payload = cls._bits_to_bytes(
            pixels[header_bits:],
            payload_length * 8,
        )

        actual_digest = hashlib.sha256(payload).digest()

        if not hmac.compare_digest(
            expected_digest,
            actual_digest,
        ):
            raise SteganographyError(
                "Hidden payload integrity check failed"
            )

        def write_payload(output):
            output.write(payload)

        return cls._atomic_write(output_file, write_payload)
