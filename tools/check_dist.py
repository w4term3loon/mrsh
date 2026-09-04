"""Validate that release archives contain source-built, platform-tagged code."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


NATIVE_SUFFIXES = (
    ".so",
    ".dylib",
    ".dll",
    ".pyd",
    ".a",
    ".lib",
    ".o",
    ".obj",
)
RUNTIME_LIBRARY_SUFFIXES = (".so", ".dylib", ".dll", ".pyd")
REQUIRED_SDIST_PATHS = {
    "pyproject.toml",
    "setup.py",
    "makefile",
    "tools/check_dist.py",
    "tools/check_release_tag.py",
    "bindings/glue/mrsh_glue.c",
    "bindings/glue/mrsh_glue.h",
    "bindings/mrshw/core.py",
    "header/fingerprint.h",
    "header/traversal.h",
    "src/fingerprint.c",
    "src/traversal.c",
}


def is_native_binary(name: str) -> bool:
    basename = Path(name).name.lower()
    return basename.endswith(NATIVE_SUFFIXES) or ".so." in basename


def is_runtime_library(name: str) -> bool:
    basename = Path(name).name.lower()
    return basename.endswith(RUNTIME_LIBRARY_SUFFIXES) or ".so." in basename


def inspect_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = [Path(name) for name in archive.getnames() if name]

    relative = {Path(*member.parts[1:]).as_posix() for member in members}
    missing = REQUIRED_SDIST_PATHS - relative
    if missing:
        raise RuntimeError(f"{path.name} is missing source files: {sorted(missing)}")

    bundled = [str(member) for member in members if is_native_binary(str(member))]
    if bundled:
        raise RuntimeError(f"{path.name} contains precompiled libraries: {bundled}")


def inspect_wheel(path: Path) -> None:
    parts = path.stem.split("-")
    if len(parts) < 5 or parts[-1] == "any":
        raise RuntimeError(
            f"{path.name} is incorrectly tagged as a platform-independent wheel"
        )

    with zipfile.ZipFile(path) as archive:
        native = [name for name in archive.namelist() if is_native_binary(name)]
        expected = [
            name
            for name in native
            if name.startswith("mrshw/libmrsh") and is_runtime_library(name)
        ]
    if len(expected) != 1 or native != expected:
        raise RuntimeError(
            f"{path.name} must contain only one native mrshw library; found {native}"
        )


def main(directory: Path) -> None:
    archives = sorted(directory.iterdir())
    if not archives:
        raise RuntimeError(f"no distributions found in {directory}")

    recognized = 0
    for archive in archives:
        if archive.name.endswith(".tar.gz"):
            inspect_sdist(archive)
            recognized += 1
        elif archive.suffix == ".whl":
            inspect_wheel(archive)
            recognized += 1

    if not recognized:
        raise RuntimeError(f"no wheel or source archives found in {directory}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} DIST_DIRECTORY")
    main(Path(sys.argv[1]))
