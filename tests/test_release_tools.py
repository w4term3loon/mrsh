from __future__ import annotations

import pytest

from tools.check_dist import is_native_binary, is_runtime_library
from tools.check_release_tag import main as check_release_tag


def test_release_tag_must_match_package_version() -> None:
    check_release_tag("v1.1.0")
    with pytest.raises(RuntimeError, match="does not match"):
        check_release_tag("v1.1.1")


@pytest.mark.parametrize(
    "name",
    ["libmrsh.so", "libmrsh.so.1", "mrsh.dll", "native.pyd", "object.o"],
)
def test_distribution_check_recognizes_native_binaries(name: str) -> None:
    assert is_native_binary(name)


def test_only_loadable_libraries_are_runtime_libraries() -> None:
    assert is_runtime_library("libmrsh.so.1")
    assert not is_runtime_library("libmrsh.o")
