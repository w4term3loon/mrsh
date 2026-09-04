from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

try:
    import resource
except ImportError:  # pragma: no cover - the standalone CLI is POSIX-only
    resource = None


NATIVE_CLI = os.environ.get("MRSH_NATIVE_CLI")


def invoke(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert NATIVE_CLI is not None
    return subprocess.run(
        [NATIVE_CLI, *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def synthetic_digest(name: str, filter_count: int) -> str:
    """Build a structurally valid zeroed digest for workload-limit tests."""
    return f"{name}:0:{filter_count}:0:{'00' * (256 * filter_count)}"


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_cli_usage_errors_and_primary_operation_conflicts() -> None:
    assert invoke("-h").returncode == 0
    assert invoke("-z").returncode > 0
    assert invoke("-L").returncode > 0
    assert invoke("-p", "-g").returncode > 0


@pytest.mark.skipif(
    NATIVE_CLI is None or not Path("/dev/full").exists(),
    reason="standalone CLI and /dev/full are required",
)
def test_native_cli_propagates_stdout_write_failures(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"native output failure regression\n" * 2_000)

    for operation in (("-p", str(sample)), ("-g", str(sample), str(sample))):
        with open("/dev/full", "wb") as output:
            result = subprocess.run(
                [NATIVE_CLI, *operation],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
                text=True,
            )
        assert result.returncode > 0


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_comparison_candidate_and_bloom_work_budgets(
    tmp_path: Path,
) -> None:
    one_filter = synthetic_digest("candidate", 1)
    too_many_candidates = tmp_path / "too-many-candidates.txt"
    too_many_candidates.write_text(
        "\n".join([one_filter] * 1_415) + "\n", encoding="ascii"
    )

    candidate_result = subprocess.run(
        [NATIVE_CLI, "-L", str(too_many_candidates)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert candidate_result.returncode > 0
    assert candidate_result.stdout == ""

    first_oversized = tmp_path / "first-oversized-fingerprint.txt"
    second_oversized = tmp_path / "second-oversized-fingerprint.txt"
    first_oversized.write_text(
        synthetic_digest("first", 1_001) + "\n", encoding="ascii"
    )
    second_oversized.write_text(
        synthetic_digest("second", 1_000) + "\n", encoding="ascii"
    )
    oversized_result = subprocess.run(
        [NATIVE_CLI, "-L", str(first_oversized), str(second_oversized)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert oversized_result.returncode > 0
    assert oversized_result.stdout == ""

    costly = synthetic_digest("work", 600)
    first = tmp_path / "first-work-list.txt"
    second = tmp_path / "second-work-list.txt"
    contents = f"{costly}\n{costly}\n"
    first.write_text(contents, encoding="ascii")
    second.write_text(contents, encoding="ascii")

    work_result = subprocess.run(
        [NATIVE_CLI, "-L", str(first), str(second)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert work_result.returncode > 0
    assert work_result.stdout == ""


@pytest.mark.skipif(
    NATIVE_CLI is None or resource is None,
    reason="standalone CLI and POSIX resource limits are required",
)
def test_native_comparison_output_budget_is_preflighted(tmp_path: Path) -> None:
    digest_list = tmp_path / "output-amplification.txt"
    labels = [f"{index:02d}-" + "x" * (65_535 - 3) for index in range(65)]
    digest_list.write_text(
        "\n".join(synthetic_digest(label, 1) for label in labels) + "\n",
        encoding="ascii",
    )
    output = tmp_path / "comparison-output.txt"

    def limit_output_file() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = 1024 * 1024 if hard == resource.RLIM_INFINITY else min(1024 * 1024, hard)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    with output.open("wb") as stream:
        result = subprocess.run(
            [NATIVE_CLI, "-L", str(digest_list)],
            check=False,
            stdout=stream,
            stderr=subprocess.PIPE,
            timeout=10,
            preexec_fn=limit_output_file,
        )

    assert result.returncode > 0, result.stderr
    assert output.stat().st_size == 0


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_printed_digest_round_trips_through_list_reader(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"native list parser regression\n" * 4_000)

    printed = invoke("-p", str(sample))
    assert printed.returncode == 0, printed.stderr
    assert printed.stdout.count(":") == 4

    digest_list = tmp_path / "digests.txt"
    digest_list.write_text(printed.stdout, encoding="ascii")
    compared = invoke("-L", str(digest_list))
    assert compared.returncode == 0, compared.stderr

    long_name = tmp_path / ("l" * 240)
    long_name.write_text(printed.stdout, encoding="ascii")
    long_name_result = invoke("-L", str(long_name))
    assert long_name_result.returncode == 0, long_name_result.stderr


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_list_reader_rejects_truncated_digest(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"malformed native digest\n" * 4_000)
    printed = invoke("-p", str(sample))
    assert printed.returncode == 0, printed.stderr

    malformed = tmp_path / "malformed.txt"
    malformed.write_text(printed.stdout.strip()[:-1] + "\n", encoding="ascii")
    result = invoke("-L", str(malformed))
    assert result.returncode > 0


@pytest.mark.skipif(
    NATIVE_CLI is None or not Path("/proc/version").is_file(),
    reason="standalone CLI and Linux procfs are required",
)
def test_native_cli_streams_virtual_regular_files_to_eof(tmp_path: Path) -> None:
    proc_version = Path("/proc/version")
    try:
        payload = proc_version.read_bytes()
    except OSError as exc:  # pragma: no cover - unusual procfs restrictions
        pytest.skip(f"cannot read /proc/version: {exc}")
    assert payload

    copied = tmp_path / "version-copy"
    copied.write_bytes(payload)
    virtual_result = invoke("-p", str(proc_version))
    copied_result = invoke("-p", str(copied))

    assert virtual_result.returncode == 0, virtual_result.stderr
    assert copied_result.returncode == 0, copied_result.stderr
    virtual_fields = virtual_result.stdout.strip().rsplit(":", 4)
    copied_fields = copied_result.stdout.strip().rsplit(":", 4)
    assert int(virtual_fields[1]) == len(payload)
    assert virtual_fields[1:] == copied_fields[1:]


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_list_reader_rejects_oversized_sparse_file_quickly(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized.txt"
    oversized.touch()
    os.truncate(oversized, 256 * 1024 * 1024 + 1)

    result = subprocess.run(
        [NATIVE_CLI, "-L", str(oversized)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode > 0


@pytest.mark.skipif(
    NATIVE_CLI is None or not hasattr(os, "mkfifo"),
    reason="standalone CLI and POSIX FIFOs are required",
)
def test_native_cli_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)

    result = subprocess.run(
        [NATIVE_CLI, "-p", str(fifo)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode > 0


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_cli_rejects_control_characters_in_output_labels(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "escape-\x1b[31m.bin"
    sample.write_bytes(b"terminal output regression" * 500)

    result = invoke("-p", str(sample))

    assert result.returncode > 0
    assert result.stdout == ""
    assert "\x1b" not in result.stderr
    assert "\\x1B" in result.stderr


@pytest.mark.skipif(
    NATIVE_CLI is None or resource is None,
    reason="standalone CLI and POSIX resource limits are required",
)
def test_recursive_scan_closes_parent_directories_before_descending(
    tmp_path: Path,
) -> None:
    root = tmp_path / "tree"
    directory = root
    for _ in range(64):
        directory = directory / "d"
    directory.mkdir(parents=True)
    (directory / "sample.bin").write_bytes(b"recursive descriptor regression" * 500)

    def limit_descriptors() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limit = 32 if hard == resource.RLIM_INFINITY else min(32, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))

    result = subprocess.run(
        [NATIVE_CLI, "-p", "-r", str(root)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        preexec_fn=limit_descriptors,
    )

    assert result.returncode == 0, result.stderr
    assert "sample.bin" in result.stdout


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_recursion_depth_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "deep"
    directory = root
    for _ in range(258):
        directory = directory / "d"
    directory.mkdir(parents=True)

    result = subprocess.run(
        [NATIVE_CLI, "-p", "-r", str(root)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode > 0


@pytest.mark.skipif(NATIVE_CLI is None, reason="standalone CLI was not built")
def test_native_scan_rejects_symlink_in_supplied_root_components(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True)
    (nested / "secret.bin").write_bytes(b"outside" * 1_000)
    (base / "link").symlink_to(outside, target_is_directory=True)

    for redirected_root in (
        str(base / "link" / "nested"),
        f"{base / 'link'}/",
    ):
        result = invoke("-p", "-r", redirected_root)
        assert result.returncode > 0
        assert result.stdout == ""


@pytest.mark.skipif(
    NATIVE_CLI is None or not sys.platform.startswith("linux"),
    reason="standalone CLI and Linux symbol interposition are required",
)
def test_native_file_symlink_target_swap_is_rejected(tmp_path: Path) -> None:
    original = tmp_path / "original.bin"
    replacement = tmp_path / "replacement.bin"
    original.write_bytes(b"original target" * 1_000)
    replacement.write_bytes(b"replacement target" * 1_000)
    linked = tmp_path / "linked.bin"
    linked.symlink_to(original)

    shim_source = tmp_path / "swap-open.c"
    shim_library = tmp_path / "swap-open.so"
    shim_source.write_text(
        r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*open_function)(const char *, int, ...);

static void maybe_swap(const char *path)
{
    static int swapped;
    const char *swap_path;
    const char *swap_target;

    swap_path = getenv("MRSH_TEST_SWAP_PATH");
    swap_target = getenv("MRSH_TEST_SWAP_TARGET");
    if (!swapped && swap_path != NULL && swap_target != NULL &&
        strcmp(path, swap_path) == 0) {
        swapped = 1;
        (void)unlink(swap_path);
        (void)symlink(swap_target, swap_path);
    }
}

int open(const char *path, int flags, ...)
{
    static open_function real_open;
    mode_t mode = 0;

    if (real_open == NULL) {
        real_open = (open_function)dlsym(RTLD_NEXT, "open");
    }
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    maybe_swap(path);
    if ((flags & O_CREAT) != 0) {
        return real_open(path, flags, mode);
    }
    return real_open(path, flags);
}

int __open_2(const char *path, int flags)
{
    static open_function real_open;

    if (real_open == NULL) {
        real_open = (open_function)dlsym(RTLD_NEXT, "__open_2");
    }
    maybe_swap(path);
    return real_open(path, flags);
}
''',
        encoding="ascii",
    )
    compiler_command = os.environ.get("CC", "cc")
    compiler = subprocess.run(
        [
            compiler_command,
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-o",
            str(shim_library),
            str(shim_source),
            "-ldl",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert compiler.returncode == 0, compiler.stderr

    environment = os.environ.copy()
    preload = []
    if environment.get("ASAN_OPTIONS"):
        asan_library = subprocess.run(
            [compiler_command, "-print-file-name=libasan.so"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if asan_library and asan_library != "libasan.so":
            preload.append(asan_library)
    if environment.get("LD_PRELOAD"):
        preload.append(environment["LD_PRELOAD"])
    preload.append(str(shim_library))
    environment["LD_PRELOAD"] = os.pathsep.join(preload)
    environment["MRSH_TEST_SWAP_PATH"] = str(linked)
    environment["MRSH_TEST_SWAP_TARGET"] = str(replacement)
    result = subprocess.run(
        [NATIVE_CLI, "-p", str(linked)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )

    assert result.returncode > 0, result.stderr
    assert result.stdout == ""
    assert linked.resolve() == replacement


@pytest.mark.skipif(
    NATIVE_CLI is None or not Path("/proc/self/fd").is_dir(),
    reason="standalone CLI and Linux procfs are required",
)
def test_native_scan_rejects_intermediate_directory_symlink_swap(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    trigger = root / "00-trigger.bin"
    trigger.touch()
    os.truncate(trigger, 128 * 1024 * 1024)
    subdirectory = root / "sub"
    subdirectory.mkdir()
    (subdirectory / "sample.bin").write_bytes(b"original" * 1_000)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sample.bin").write_bytes(b"outside" * 1_000)
    moved = tmp_path / "moved-original"

    process = subprocess.Popen(
        [NATIVE_CLI, "-p", "-r", str(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stopped = False
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process.poll() is None:
            descriptors = Path(f"/proc/{process.pid}/fd")
            try:
                targets = [os.readlink(entry) for entry in descriptors.iterdir()]
            except (FileNotFoundError, PermissionError):
                targets = []
            if any(str(trigger) in target for target in targets):
                os.kill(process.pid, signal.SIGSTOP)
                stopped = True
                break
            time.sleep(0.001)
        assert stopped, "CLI completed before its opened trigger could be observed"

        subdirectory.rename(moved)
        subdirectory.symlink_to(outside, target_is_directory=True)
        os.kill(process.pid, signal.SIGCONT)
        stopped = False
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode and process.returncode > 0, (stdout, stderr)
    finally:
        if stopped and process.poll() is None:
            os.kill(process.pid, signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.communicate()
