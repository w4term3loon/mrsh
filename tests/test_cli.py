from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import mrshw


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mrshw.cli", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_reports_package_version() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    assert mrshw.__version__ in result.stdout


def test_cli_hash_and_compare_files(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"CLI regression data" * 500)

    hashed = run_cli("hash", str(sample))
    compared = run_cli("compare", str(sample), str(sample))

    assert hashed.returncode == 0, hashed.stderr
    assert hashed.stdout.strip() == mrshw.hash(str(sample))
    assert compared.returncode == 0, compared.stderr
    assert "Similarity score: 100" in compared.stdout


def test_cli_compares_long_digest_arguments(payload: bytes) -> None:
    first = mrshw.hash((payload, "first"))
    second = mrshw.hash((payload, "second"))

    result = run_cli("compare", first, second)

    assert result.returncode == 0, result.stderr
    assert "Similarity score: 100" in result.stdout


def test_cli_threshold_controls_status_and_is_validated(
    payload: bytes, different_payload: bytes
) -> None:
    first = mrshw.hash((payload, "first"))
    different = mrshw.hash((different_payload, "different"))

    below_threshold = run_cli("compare", first, different, "--threshold", "100")
    invalid = run_cli("compare", first, different, "--threshold", "101")

    assert below_threshold.returncode == 1
    assert "Similarity score:" in below_threshold.stdout
    assert invalid.returncode == 2
