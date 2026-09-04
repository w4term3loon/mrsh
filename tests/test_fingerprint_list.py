from __future__ import annotations

import copy
import os
import pickle
from pathlib import Path

import pytest

import mrshw
import mrshw.core as mrsh_core
import mrshw.utils as mrsh_utils
from mrshw.utils import batch_compare, scan_directory


def synthetic_digest(name: str, filter_count: int) -> str:
    return f"{name}:0:{filter_count}:0:{'00' * (256 * filter_count)}"


def test_list_comparison_and_thresholds(payload: bytes) -> None:
    with mrshw.FingerprintList(
        [(payload, "first"), (payload, "second")]
    ) as fingerprints:
        results = fingerprints.compare_all(threshold=100)
        assert len(results) == 1
        assert results[0].score == 100
        assert {results[0].hash1, results[0].hash2} == {"first", "second"}

        for threshold in (0, 1, 99, 100):
            assert all(0 <= result.score <= 100 for result in fingerprints.compare_all(threshold))


def test_comparison_work_budgets_are_preflighted() -> None:
    with mrshw.Fingerprint.from_digest(
        synthetic_digest("first", 1_001)
    ) as first, mrshw.Fingerprint.from_digest(
        synthetic_digest("second", 1_000)
    ) as second:
        with pytest.raises(mrshw.MRSHwError):
            first.compare(second)

    costly = synthetic_digest("work", 600)
    with mrshw.FingerprintList.from_digest(
        f"{costly}\n{costly}"
    ) as first_list, mrshw.FingerprintList.from_digest(
        f"{costly}\n{costly}"
    ) as second_list:
        with pytest.raises(mrshw.MRSHwError):
            first_list.compare_with(second_list)


@pytest.mark.parametrize("threshold", [-1, 101])
def test_threshold_out_of_range_is_rejected(payload: bytes, threshold: int) -> None:
    with mrshw.FingerprintList([(payload, "a"), (payload, "b")]) as fingerprints:
        with pytest.raises(ValueError):
            fingerprints.compare_all(threshold)


@pytest.mark.parametrize("threshold", [True, 1.5, "50", None])
def test_threshold_must_be_an_integer(payload: bytes, threshold: object) -> None:
    with mrshw.FingerprintList([(payload, "a"), (payload, "b")]) as fingerprints:
        with pytest.raises(TypeError):
            fingerprints.compare_all(threshold)  # type: ignore[arg-type]


def test_list_digest_copy_pickle_and_close(payload: bytes, different_payload: bytes) -> None:
    original = mrshw.FingerprintList(
        [(payload, "first"), (different_payload, "second")]
    )
    digest = original.hexdigest()
    restored = mrshw.FingerprintList.from_digest(digest)
    shallow = copy.copy(original)
    deep = copy.deepcopy(original)
    unpickled = pickle.loads(pickle.dumps(original))

    original.close()
    original.close()
    assert original.closed
    with pytest.raises(mrshw.MRSHwError):
        original.hexdigest()
    with pytest.raises(mrshw.MRSHwError):
        len(original)
    with pytest.raises(mrshw.MRSHwError):
        original.add(payload)

    try:
        for independent in (restored, shallow, deep, unpickled):
            assert independent.hexdigest() == digest
    finally:
        restored.close()
        shallow.close()
        deep.close()
        unpickled.close()


def test_list_parser_accepts_empty_input_and_one_trailing_newline(payload: bytes) -> None:
    digest = mrshw.hash((payload, "line"))
    with mrshw.FingerprintList.from_digest("") as empty:
        assert len(empty) == 0
        assert empty.hexdigest() == ""
    with mrshw.FingerprintList.from_digest(digest + "\n") as restored:
        assert len(restored) == 1
        assert restored.hexdigest() == digest


def test_multi_item_add_is_atomic(payload: bytes, tmp_path: Path) -> None:
    with mrshw.FingerprintList((payload, "first")) as fingerprints:
        before = fingerprints.hexdigest()
        with pytest.raises(mrshw.MRSHwError):
            fingerprints.add([(payload, "second"), tmp_path / "missing.bin"])
        assert fingerprints.hexdigest() == before


def test_nested_list_input_rejects_cycles_and_excessive_depth(
    payload: bytes,
) -> None:
    cycle = []
    cycle.append(cycle)
    deeply_nested: object = (payload, "nested")
    for _ in range(mrsh_core._MAX_INPUT_NESTING + 1):
        deeply_nested = [deeply_nested]

    with mrshw.FingerprintList((payload, "kept")) as fingerprints:
        before = fingerprints.hexdigest()
        with pytest.raises(ValueError, match="container cycle"):
            fingerprints.add(cycle)
        with pytest.raises(ValueError, match="nesting limit"):
            fingerprints.add(deeply_nested)
        assert fingerprints.hexdigest() == before


def test_nested_list_input_bounds_shared_graph_expansion(
    payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared: object = [(payload, "leaf")]
    for _ in range(8):
        shared = [shared, shared]
    monkeypatch.setattr(mrsh_core, "_MAX_INPUT_NODES", 32)

    with mrshw.FingerprintList() as fingerprints:
        with pytest.raises(ValueError, match="node limit"):
            fingerprints.add(shared)
        assert len(fingerprints) == 0


def test_scan_directory_defaults_to_all_files_without_chdir(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"alpha" * 1_000)
    (tmp_path / "b.bin").write_bytes(b"beta" * 1_000)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "c.TXT").write_bytes(b"gamma" * 1_000)
    original_cwd = Path.cwd()

    with scan_directory(tmp_path) as first, scan_directory(tmp_path) as second:
        lines = first.hexdigest().splitlines()
        assert first.hexdigest() == second.hexdigest()
        assert len(lines) == 3
        assert [line.split(":", 1)[0] for line in lines] == [
            "a.txt",
            "b.bin",
            "nested/c.TXT",
        ]

    assert Path.cwd() == original_cwd


def test_scan_directory_normalizes_extensions(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"alpha" * 1_000)
    (tmp_path / "b.bin").write_bytes(b"beta" * 1_000)

    with scan_directory(tmp_path, extensions=["TXT"], recursive=False) as fingerprints:
        assert fingerprints.hexdigest().split(":", 1)[0] == "a.txt"

    with scan_directory(tmp_path, extensions=[], recursive=False) as fingerprints:
        assert len(fingerprints) == 0


def test_scan_directory_bounds_and_validates_extension_iterables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    consumed = []

    def extensions():
        index = 0
        while True:
            consumed.append(index)
            yield f"extension-{index}"
            index += 1

    monkeypatch.setattr(mrsh_utils, "_MAX_EXTENSION_FILTERS", 2)
    with pytest.raises(mrshw.MRSHwError, match="2-item limit"):
        scan_directory(tmp_path, extensions=extensions())
    assert consumed == [0, 1, 2]

    with pytest.raises(TypeError, match="not one string"):
        scan_directory(tmp_path, extensions="bin")

    monkeypatch.setattr(mrsh_utils, "_MAX_EXTENSION_FILTER_BYTES", 7)
    with pytest.raises(mrshw.MRSHwError, match="7-byte limit"):
        scan_directory(tmp_path, extensions=["abc", "def"])
    with pytest.raises(mrshw.MRSHwError, match="7-byte limit"):
        scan_directory(tmp_path, extensions=["x" * 8])


def test_scan_directory_does_not_follow_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "regular.bin").write_bytes(b"regular" * 1_000)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside" * 1_000)
    (root / "escape.bin").symlink_to(outside)

    with scan_directory(root) as fingerprints:
        assert len(fingerprints) == 1
        assert fingerprints.hexdigest().split(":", 1)[0] == "regular.bin"

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        scan_directory(linked_root)


def test_scans_reject_symlinks_in_supplied_root_components(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True)
    (nested / "secret.bin").write_bytes(b"outside" * 1_000)
    (base / "link").symlink_to(outside, target_is_directory=True)
    redirected_root = base / "link" / "nested"

    with pytest.raises(mrshw.MRSHwError, match="symlink"):
        scan_directory(redirected_root)

    with mrshw.FingerprintList() as fingerprints:
        with pytest.raises(mrshw.MRSHwError):
            fingerprints.add(redirected_root, recursive=True)
        with pytest.raises(mrshw.MRSHwError):
            fingerprints.add(f"{base / 'link'}/", recursive=True)
        assert len(fingerprints) == 0


def test_batch_compare_valid_files(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"same data" * 1_000)
    second.write_bytes(first.read_bytes())

    results = batch_compare([first, second], threshold=100)
    assert len(results) == 1
    assert results[0].score == 100


def test_batch_compare_rejects_missing_files(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        batch_compare([tmp_path / "missing.bin"])


def test_scan_and_batch_paths_are_bounded_before_splitting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mrsh_utils, "_MAX_PATH_BYTES", 8)

    with pytest.raises(ValueError, match="8-byte limit"):
        scan_directory("x" * 9)
    with pytest.raises(ValueError, match="8-byte limit"):
        batch_compare(["x" * 9])


def test_batch_compare_does_not_lexically_collapse_symlink_dotdot(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    base.mkdir()
    (base / "safe.bin").write_bytes(b"lexically selected" * 500)
    outside = tmp_path / "outside"
    (outside / "inner").mkdir(parents=True)
    (outside / "safe.bin").write_bytes(b"kernel selected" * 500)
    (base / "link").symlink_to(outside / "inner", target_is_directory=True)

    ambiguous = base / "link" / ".." / "safe.bin"
    with pytest.raises(mrshw.MRSHwError, match="symlink"):
        batch_compare([ambiguous])


def test_batch_compare_rejects_intermediate_directory_symlink_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    subdirectory = root / "sub"
    subdirectory.mkdir()
    sample = subdirectory / "sample.bin"
    sample.write_bytes(b"original" * 1_000)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sample.bin").write_bytes(b"outside" * 1_000)
    moved = tmp_path / "moved-original"
    original_open = os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "sub" and dir_fd is not None and not swapped:
            swapped = True
            subdirectory.rename(moved)
            subdirectory.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(mrsh_utils.os, "open", swap_before_open)

    with pytest.raises(mrshw.MRSHwError, match="changed while opening"):
        batch_compare([sample])


def test_batch_compare_bounds_iterable_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    third = tmp_path / "third.bin"
    for path in (first, second, third):
        path.write_bytes(b"bounded batch" * 500)
    consumed = []

    def paths():
        for path in (first, second, third):
            consumed.append(path)
            yield path

    monkeypatch.setattr(mrsh_utils, "_MAX_LIST_ENTRIES", 1)

    with pytest.raises(mrshw.MRSHwError, match="file limit"):
        batch_compare(paths())
    assert consumed == [first, second]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX filename bytes")
def test_scan_directory_preserves_non_utf8_filename_bytes(tmp_path: Path) -> None:
    name = os.fsdecode(b"bad-\xff.bin")
    sample = tmp_path / name
    sample.write_bytes(b"filesystem byte regression" * 500)

    with scan_directory(tmp_path) as fingerprints:
        assert fingerprints.hexdigest().split(":", 1)[0] == name


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX filename bytes")
def test_batch_compare_preserves_non_utf8_filename_bytes(tmp_path: Path) -> None:
    first_name = os.fsdecode(b"first-\xff.bin")
    second_name = os.fsdecode(b"second-\xfe.bin")
    first = tmp_path / first_name
    second = tmp_path / second_name
    first.write_bytes(b"filesystem byte comparison" * 500)
    second.write_bytes(first.read_bytes())

    results = batch_compare([first, second], threshold=100)

    assert len(results) == 1
    assert {results[0].hash1, results[0].hash2} == {first_name, second_name}


def test_native_directory_add_skips_entry_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    regular = root / "regular.bin"
    regular.write_bytes(b"regular" * 1_000)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside" * 1_000)
    linked = root / "linked.bin"
    linked.symlink_to(outside)

    with mrshw.FingerprintList() as fingerprints:
        fingerprints.add(root, recursive=True)
        assert len(fingerprints) == 1

        fingerprints.add(linked)
        assert len(fingerprints) == 2


def test_scan_rejects_intermediate_directory_swapped_to_symlink_after_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    subdirectory = root / "sub"
    subdirectory.mkdir()
    sample = subdirectory / "sample.bin"
    sample.write_bytes(b"original" * 1_000)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sample.bin").write_bytes(b"outside" * 1_000)
    moved = tmp_path / "moved-original"
    original_open = mrsh_utils._open_scanned_file
    swapped = False

    def swap_then_open(root_descriptor, parts, directory_identities, identity):
        nonlocal swapped
        if not swapped:
            swapped = True
            subdirectory.rename(moved)
            subdirectory.symlink_to(outside, target_is_directory=True)
        return original_open(root_descriptor, parts, directory_identities, identity)

    monkeypatch.setattr(mrsh_utils, "_open_scanned_file", swap_then_open)

    with pytest.raises(mrshw.MRSHwError):
        scan_directory(root)


def test_scan_bounds_all_visited_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "one.special").mkdir()
    (tmp_path / "two.special").mkdir()
    monkeypatch.setattr(mrsh_utils, "_MAX_SCAN_ENTRIES", 1)

    with pytest.raises(mrshw.MRSHwError, match="entry limit"):
        scan_directory(tmp_path, recursive=False)


def test_open_descriptor_ingestion_preserves_offset_and_ownership(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    payload = b"descriptor ingestion" * 1_000
    sample.write_bytes(payload)
    descriptor = os.open(sample, os.O_RDONLY)
    try:
        os.lseek(descriptor, 7, os.SEEK_SET)
        with mrshw.FingerprintList() as fingerprints, mrshw.Fingerprint(
            (payload, "sample.bin")
        ) as expected:
            fingerprints._add_open_fd(descriptor, "sample.bin")
            assert len(fingerprints) == 1
            assert fingerprints.hexdigest() == expected.hexdigest()
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 7
        os.fstat(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptors")
def test_open_descriptor_ingestion_rejects_nonregular_files() -> None:
    read_descriptor, write_descriptor = os.pipe()
    try:
        with mrshw.FingerprintList() as fingerprints:
            with pytest.raises(mrshw.MRSHwError):
                fingerprints._add_open_fd(read_descriptor, "pipe")
        os.fstat(read_descriptor)
        os.fstat(write_descriptor)
    finally:
        os.close(read_descriptor)
        os.close(write_descriptor)


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="requires procfs")
def test_adding_files_does_not_leak_descriptors(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"descriptor regression" * 500)
    baseline = len(os.listdir("/proc/self/fd"))

    with mrshw.FingerprintList() as fingerprints:
        for index in range(64):
            fingerprints.add((str(sample), f"sample-{index}"))
        assert len(os.listdir("/proc/self/fd")) <= baseline + 2
