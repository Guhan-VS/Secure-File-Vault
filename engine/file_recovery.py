
import os
import stat
import tempfile
from pathlib import Path

from engine.container_inspector import VaultContainerInspector
from engine.file_encryption import VaultFileEngine
from engine.security_validator import SecurityValidator


class VaultFileRecovery:

    MAX_COLLISION_ATTEMPTS = 10000
    COPY_BUFFER_SIZE = 1024 * 1024
    MAX_FILENAME_UTF16_UNITS = 255

    WINDOWS_RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "CONIN$", "CONOUT$",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
        *(f"COM{i}" for i in ("¹", "²", "³")),
        *(f"LPT{i}" for i in ("¹", "²", "³")),
    }

    @classmethod
    def _validate_filename(cls, filename):

        if not isinstance(filename, str):
            raise ValueError("Invalid recovery filename")

        if not filename or filename in (".", ".."):
            raise ValueError("Invalid recovery filename")

        try:
            utf16_units = len(
                filename.encode("utf-16-le")
            ) // 2
        except UnicodeEncodeError as exc:
            raise ValueError(
                "Invalid Unicode in recovery filename"
            ) from exc

        if utf16_units > cls.MAX_FILENAME_UTF16_UNITS:
            raise ValueError("Recovery filename is too long")

        if any(char in filename for char in '<>:"/\\|?*'):
            raise ValueError("Unsafe recovery filename")

        if any(ord(char) < 32 for char in filename):
            raise ValueError(
                "Invalid control character in filename"
            )

        if filename.endswith((" ", ".")):
            raise ValueError("Invalid Windows filename")

        # Windows treats trailing spaces and dots in path components
        # as insignificant. Check the name before its first extension.
        device_name = filename.split(".", 1)[0].rstrip(" .").upper()

        if device_name in cls.WINDOWS_RESERVED_NAMES:
            raise ValueError("Reserved Windows filename")

        return filename

    @staticmethod
    def _get_available_path(directory, filename):

        original = Path(filename)
        candidate = directory / filename

        if not candidate.exists() and not candidate.is_symlink():
            return candidate

        stem = original.stem
        suffix = original.suffix

        for index in range(
            1,
            VaultFileRecovery.MAX_COLLISION_ATTEMPTS + 1
        ):

            candidate = directory / f"{stem} ({index}){suffix}"

            if not candidate.exists() and not candidate.is_symlink():
                return candidate

        raise FileExistsError(
            "Unable to find an available recovery filename"
        )

    @classmethod
    def _create_container_snapshot(cls, source, directory):

        source = Path(source)
        directory = Path(directory)

        if source.is_symlink():
            raise ValueError(
                "Symbolic link containers are not supported"
            )

        fd, temporary_path = tempfile.mkstemp(
            prefix=".vaultcrypt-recovery-",
            suffix=".tmp",
            dir=directory
        )

        temporary_path = Path(temporary_path)

        try:
            with source.open("rb") as src:

                initial_stat = os.fstat(src.fileno())

                if not stat.S_ISREG(initial_stat.st_mode):
                    raise ValueError(
                        "Container must be a regular file"
                    )

                initial_size = initial_stat.st_size

                if initial_size < 1:
                    raise ValueError("Container cannot be empty")

                if initial_size > SecurityValidator.MAX_CONTAINER_SIZE:
                    raise ValueError(
                        "Container exceeds maximum supported size"
                    )

                initial_signature = VaultFileEngine._file_signature(
                    initial_stat
                )

                initial_path_stat = source.stat()

                if not stat.S_ISREG(initial_path_stat.st_mode):
                    raise ValueError(
                        "Container path must reference a regular file"
                    )

                initial_path_signature = (
                    VaultFileEngine._path_signature(
                        initial_path_stat
                    )
                )

                with os.fdopen(fd, "wb") as out:

                    remaining = initial_size

                    while remaining > 0:

                        chunk = src.read(
                            min(cls.COPY_BUFFER_SIZE, remaining)
                        )

                        if not chunk:
                            raise ValueError(
                                "Container was truncated during snapshot creation"
                            )

                        out.write(chunk)
                        remaining -= len(chunk)

                    if src.read(1):
                        raise ValueError(
                            "Container grew during snapshot creation"
                        )

                    final_stat = os.fstat(src.fileno())

                    final_signature = (
                        VaultFileEngine._file_signature(final_stat)
                    )

                    try:
                        final_path_stat = source.stat()
                    except OSError as exc:
                        raise ValueError(
                            "Container disappeared during snapshot creation"
                        ) from exc

                    if not stat.S_ISREG(final_path_stat.st_mode):
                        raise ValueError(
                            "Container path was replaced during snapshot creation"
                        )

                    final_path_signature = (
                        VaultFileEngine._path_signature(
                            final_path_stat
                        )
                    )

                    if initial_signature != final_signature:
                        raise ValueError(
                            "Container changed during snapshot creation"
                        )

                    if (
                        initial_path_signature
                        != final_path_signature
                    ):
                        raise ValueError(
                            "Container was replaced during snapshot creation"
                        )

                    out.flush()
                    os.fsync(out.fileno())

            return temporary_path

        except Exception:

            try:
                os.close(fd)
            except OSError:
                pass

            try:
                if temporary_path.exists():
                    temporary_path.unlink()
            except OSError:
                pass

            raise

    @classmethod
    def recover_file(
        cls,
        container_path,
        destination_directory,
        password
    ):

        container_path = SecurityValidator.validate_container_source(
            container_path
        )

        SecurityValidator.validate_password(password)

        destination_directory = Path(destination_directory)

        if destination_directory.is_symlink():
            raise ValueError(
                "Symbolic link recovery directories are not supported"
            )

        if not destination_directory.is_dir():
            raise NotADirectoryError(destination_directory)

        snapshot_path = None

        try:
            snapshot_path = cls._create_container_snapshot(
                container_path,
                destination_directory
            )

            information = VaultContainerInspector.inspect(
                snapshot_path,
                password
            )

            if not information["metadata_authenticated"]:
                raise ValueError(
                    "Container metadata authentication failed"
                )

            filename = cls._validate_filename(
                information["original_filename"]
            )

            for _ in range(cls.MAX_COLLISION_ATTEMPTS):

                destination = cls._get_available_path(
                    destination_directory,
                    filename
                )

                try:
                    SecurityValidator.validate_source_destination(
                        snapshot_path,
                        destination
                    )

                    SecurityValidator.validate_destination(
                        destination
                    )

                    return VaultFileEngine.decrypt_file(
                        snapshot_path,
                        destination,
                        password
                    )

                except FileExistsError:
                    continue

            raise FileExistsError(
                "Recovery failed: too many filename collisions"
            )

        finally:
            if (
                snapshot_path is not None
                and snapshot_path.exists()
            ):
                snapshot_path.unlink()
