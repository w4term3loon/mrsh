from __future__ import annotations

import copy
import hashlib
import os
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

import mrshw
import mrshw.core as core


def test_known_mrsh_vector_is_compatible() -> None:
    data = b"".join(
        f"MRSH regression vector line {i:08d} alpha beta gamma delta epsilon\n".encode()
        for i in range(1, 1001)
    )

    digest = mrshw.hash((data, "vector"))

    assert len(data) == 68_000
    assert len(digest) == 530
    assert digest.startswith(
        "vector:68000:1:35:"
        "030022000000800000002000000B000A0004080004000020600200020808001200010000124180048040082000400000200200"
    )
    assert hashlib.sha256(digest.encode("ascii")).hexdigest() == (
        "e85e5fb6d2dad9d16c6762b38538bf8c4480883b21d8452cc47be2ea8672a28b"
    )


def test_known_nonidentical_similarity_score_is_compatible() -> None:
    base = bytearray(
        b"".join(
            f"MRSH comparison vector line {i:08d} alpha beta gamma delta epsilon\n".encode()
            for i in range(1, 5_001)
        )
    )
    changed = bytearray(base)
    changed[5_000:9_000] = b"X" * 4_000
    assert len(base) == 340_000

    with mrshw.Fingerprint((bytes(base), "base")) as original, mrshw.Fingerprint(
        (bytes(changed), "changed")
    ) as variant:
        assert original.compare(variant) == 98


@pytest.mark.parametrize(
    "length",
    [0, 1, 39, 40, 41, 42, 158, 159, 160, 161, 199, 200, 201, 65_535, 65_536, 65_537, 68_000],
)
def test_streaming_file_hash_matches_buffer_hash_at_boundaries(
    tmp_path: Path, length: int
) -> None:
    data = bytes((index * 131 + 17) & 0xFF for index in range(length))
    sample = tmp_path / "streamed.bin"
    sample.write_bytes(data)

    with mrshw.Fingerprint((data, "same")) as buffered, mrshw.Fingerprint(
        (sample, "same")
    ) as streamed:
        assert streamed.hexdigest() == buffered.hexdigest()


def test_hash_metadata_and_similarity_score(payload: bytes) -> None:
    with mrshw.Fingerprint((payload, "sample")) as first, mrshw.Fingerprint(
        (payload, "copy")
    ) as second:
        assert first.metadata() == mrshw.Metadata("sample", len(payload), 1)
        assert first.compare(second) == 100
        assert mrshw.compare(first, second) == 100
        assert mrshw.diff(first.hexdigest(), second.hexdigest()) == 100


def test_empty_input_is_deterministic_and_initialized() -> None:
    with mrshw.Fingerprint((b"", "empty")) as first, mrshw.Fingerprint(
        (b"", "empty")
    ) as second:
        digest = first.hexdigest()
        assert first.metadata() == mrshw.Metadata("empty", 0, 1)
        assert digest == second.hexdigest()
        assert digest.startswith("empty:0:1:0:")
        assert digest.endswith("00" * 256)
        assert first.compare(second) == 100


def test_update_atomically_replaces_the_fingerprint(
    payload: bytes, different_payload: bytes
) -> None:
    with mrshw.Fingerprint((payload, "before")) as fingerprint:
        fingerprint.update((different_payload, "after"))
        with mrshw.Fingerprint((different_payload, "after")) as expected:
            assert fingerprint.hexdigest() == expected.hexdigest()
            assert fingerprint.metadata().name == "after"


def test_failed_update_preserves_the_previous_fingerprint(payload: bytes, tmp_path) -> None:
    with mrshw.Fingerprint((payload, "before")) as fingerprint:
        digest = fingerprint.hexdigest()
        with pytest.raises(mrshw.MRSHwError):
            fingerprint.update(tmp_path / "missing.bin")
        assert fingerprint.hexdigest() == digest


def test_context_manager_and_close_are_idempotent(payload: bytes) -> None:
    fingerprint = mrshw.Fingerprint((payload, "owned"))
    with fingerprint as entered:
        assert entered is fingerprint
        assert not fingerprint.closed

    assert fingerprint.closed
    fingerprint.close()

    with pytest.raises(mrshw.MRSHwError):
        fingerprint.hexdigest()
    with pytest.raises(mrshw.MRSHwError):
        fingerprint.metadata()
    with pytest.raises(mrshw.MRSHwError):
        fingerprint.update(payload)


def test_copy_and_pickle_have_independent_ownership(payload: bytes) -> None:
    original = mrshw.Fingerprint((payload, "copy-source"))
    shallow = copy.copy(original)
    deep = copy.deepcopy(original)
    restored = pickle.loads(pickle.dumps(original))
    digest = original.hexdigest()

    original.close()
    try:
        assert shallow.hexdigest() == digest
        assert deep.hexdigest() == digest
        assert restored.hexdigest() == digest
    finally:
        shallow.close()
        deep.close()
        restored.close()


@pytest.mark.parametrize(
    "label", ["x" * 1_024, "x" * 65_535, "é" * 512, "namespace:sample"]
)
def test_long_utf8_and_colon_labels_round_trip(
    payload: bytes, label: str
) -> None:
    with mrshw.Fingerprint((payload, label)) as fingerprint:
        assert fingerprint.metadata().name == label
        digest = fingerprint.hexdigest()
    with mrshw.Fingerprint.from_digest(digest) as restored:
        assert restored.metadata().name == label
        assert restored.hexdigest() == digest


@pytest.mark.parametrize(
    "label",
    [
        "x" * 65_536,
        "é" * 32_768,
        "has\nnewline",
        "has\rreturn",
        "has\0nul",
        "has\ttab",
        "has\x1bescape",
        "has\x7fdelete",
        "explicit-\udcff",
    ],
)
def test_unsafe_or_oversized_labels_are_rejected(payload: bytes, label: str) -> None:
    with pytest.raises((ValueError, mrshw.MRSHwError)):
        mrshw.Fingerprint((payload, label))


def test_path_longer_than_legacy_fixed_buffer_is_supported(tmp_path) -> None:
    directory = tmp_path
    for index in range(4):
        directory = directory / (f"segment-{index}-" + "x" * 45)
    directory.mkdir(parents=True)
    sample = directory / "sample.bin"
    sample.write_bytes(b"long path regression" * 500)
    assert len(os.fsencode(sample)) > 200

    with mrshw.Fingerprint(sample) as fingerprint:
        assert fingerprint.metadata().name == str(sample)


def test_explicit_paths_are_bounded_before_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core, "_MAX_PATH_BYTES", 8)

    with pytest.raises(ValueError, match="8-byte limit"):
        mrshw.Fingerprint(("x" * 9, "short-label"))


def test_from_digest_round_trip(payload: bytes) -> None:
    digest = mrshw.hash((payload, "round-trip"))

    with mrshw.Fingerprint.from_digest(digest) as restored:
        assert restored.hexdigest() == digest
        assert restored.metadata() == mrshw.Metadata("round-trip", len(payload), 1)


def test_digest_metadata_supports_uint64_file_sizes(payload: bytes) -> None:
    digest = mrshw.hash((payload, "large-metadata"))
    name, _, filters, blocks, hex_filters = digest.rsplit(":", 4)
    declared_size = 2**32 + 17
    large_digest = f"{name}:{declared_size}:{filters}:{blocks}:{hex_filters}"

    with mrshw.Fingerprint.from_digest(large_digest) as restored:
        assert restored.metadata().size == declared_size
        assert restored.hexdigest() == large_digest


@pytest.mark.parametrize("threshold", [101, True])
def test_scalar_compare_validates_threshold(payload: bytes, threshold: object) -> None:
    with mrshw.Fingerprint((payload, "first")) as first, mrshw.Fingerprint(
        (payload, "second")
    ) as second:
        digest1 = first.hexdigest()
        digest2 = second.hexdigest()
        with pytest.raises((TypeError, ValueError)):
            mrshw.compare(first, second, threshold=threshold)  # type: ignore[arg-type]
        with pytest.raises((TypeError, ValueError)):
            mrshw.compare(digest1, digest2, threshold=threshold)  # type: ignore[arg-type]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
def test_direct_hash_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import mrshw, sys; mrshw.hash(sys.argv[1])",
            str(fifo),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode != 0


def test_invalid_library_override_is_authoritative(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["MRSHW_LIBRARY"] = str(tmp_path / "missing-native-library.so")

    result = subprocess.run(
        [sys.executable, "-c", "import mrshw"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=5,
    )

    assert result.returncode != 0
    assert "MRSHW_LIBRARY" in result.stderr


@pytest.mark.parametrize(
    ("factory_name", "destroy_name", "class_name"),
    [
        ("fp_init", "fp_destroy", "Fingerprint"),
        ("fpl_init", "fpl_destroy", "FingerprintList"),
    ],
)
def test_pointer_transfer_cleans_up_if_instance_creation_fails(
    monkeypatch: pytest.MonkeyPatch,
    factory_name: str,
    destroy_name: str,
    class_name: str,
) -> None:
    pointer = getattr(core.lib, factory_name)()
    assert pointer
    native_destroy = getattr(core.lib, destroy_name)
    destroyed = []

    def tracked_destroy(value: int) -> None:
        destroyed.append(value)
        native_destroy(value)

    def fail_lock_creation() -> None:
        raise MemoryError("simulated lock allocation failure")

    monkeypatch.setattr(core.lib, destroy_name, tracked_destroy)
    monkeypatch.setattr(core.threading, "RLock", fail_lock_creation)

    with pytest.raises(MemoryError):
        getattr(core, class_name)._from_pointer(pointer)

    assert destroyed == [pointer]
