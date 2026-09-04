"""Require a release tag to match the package version exactly."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main(tag: str) -> None:
    version_file = ROOT / "bindings" / "mrshw" / "_version.py"
    version = runpy.run_path(str(version_file)).get("__version__")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"could not read a package version from {version_file}")
    expected = f"v{version}"
    if tag != expected:
        raise RuntimeError(f"release tag {tag!r} does not match {expected!r}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} RELEASE_TAG")
    main(sys.argv[1])
