"""Convenience helpers for directory and batch operations."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from .core import (
    Comparison,
    FingerprintList,
    MRSHwError,
    _MAX_LIST_ENTRIES,
    _MAX_PATH_BYTES,
    _MAX_SCAN_DEPTH,
    _MAX_SCAN_ENTRIES,
    _MAX_SCAN_PATH_BYTES,
    _validate_threshold,
)


_MAX_EXTENSION_FILTERS = 4096
_MAX_EXTENSION_FILTER_BYTES = 1024 * 1024


def _normalized_extensions(extensions: Optional[Iterable[str]]) -> Optional[set[str]]:
    if extensions is None:
        return None
    if isinstance(extensions, (str, bytes)):
        raise TypeError("extensions must be an iterable of strings, not one string")
    normalized = set()
    encoded_bytes = 0
    for index, extension in enumerate(extensions):
        if index >= _MAX_EXTENSION_FILTERS:
            raise MRSHwError(
                f"extension filter exceeds the {_MAX_EXTENSION_FILTERS}-item limit"
            )
        if not isinstance(extension, str):
            raise TypeError("extensions must contain only strings")
        if not extension:
            raise ValueError("extensions cannot contain an empty string")
        character_bytes_floor = len(extension) + (not extension.startswith("."))
        if character_bytes_floor > _MAX_EXTENSION_FILTER_BYTES - encoded_bytes:
            raise MRSHwError(
                "extension filter exceeds the "
                f"{_MAX_EXTENSION_FILTER_BYTES}-byte limit"
            )
        if "\0" in extension or os.sep in extension or (
            os.altsep is not None and os.altsep in extension
        ):
            raise ValueError("extensions cannot contain NUL or path separators")
        normalized_extension = (
            extension if extension.startswith(".") else f".{extension}"
        ).lower()
        extension_bytes = len(os.fsencode(normalized_extension))
        if extension_bytes > _MAX_EXTENSION_FILTER_BYTES - encoded_bytes:
            raise MRSHwError(
                "extension filter exceeds the "
                f"{_MAX_EXTENSION_FILTER_BYTES}-byte limit"
            )
        encoded_bytes += extension_bytes
        normalized.add(normalized_extension)
    return normalized


_Identity = Tuple[int, int]
_Parts = Tuple[str, ...]


def _identity(attributes: os.stat_result) -> _Identity:
    return attributes.st_dev, attributes.st_ino


def _secure_open_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW") or (directory and not hasattr(os, "O_DIRECTORY")):
        raise MRSHwError("secure directory scanning is unavailable on this platform")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _bounded_path_text(path: Union[str, os.PathLike[str]]) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or os.PathLike object")
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str):
        raise TypeError("path must resolve to a string")
    if len(raw_path) > _MAX_PATH_BYTES:
        raise ValueError(f"path exceeds the {_MAX_PATH_BYTES}-byte limit")
    encoded = os.fsencode(raw_path)
    if len(encoded) > _MAX_PATH_BYTES:
        raise ValueError(f"path exceeds the {_MAX_PATH_BYTES}-byte limit")
    if b"\0" in encoded:
        raise ValueError("path cannot contain a NUL character")
    return raw_path


def _open_explicit_path_no_follow(path: Path, *, directory: bool) -> int:
    """Open a path component by component from a pinned root or cwd."""
    raw_path = _bounded_path_text(path)

    anchor = os.sep if os.path.isabs(raw_path) else "."
    components = tuple(
        component
        for component in raw_path.split(os.sep)
        if component not in ("", ".")
    )
    try:
        descriptor = os.open(anchor, _secure_open_flags(directory=True))
    except OSError as exc:
        raise MRSHwError(f"opening path anchor failed for {path!r}") from exc

    try:
        if not components:
            if directory:
                return descriptor
            raise IsADirectoryError(f"not a regular file: {path!r}")

        for index, component in enumerate(components):
            final = index + 1 == len(components)
            expect_directory = directory or not final
            try:
                expected = os.stat(
                    component, dir_fd=descriptor, follow_symlinks=False
                )
            except FileNotFoundError as exc:
                raise FileNotFoundError(f"path not found: {path!r}") from exc
            except OSError as exc:
                raise MRSHwError(
                    f"inspecting path component failed: {component!r}"
                ) from exc

            if stat.S_ISLNK(expected.st_mode):
                raise MRSHwError(f"path component is a symlink: {component!r}")
            if expect_directory and not stat.S_ISDIR(expected.st_mode):
                raise NotADirectoryError(
                    f"path component is not a directory: {component!r}"
                )
            if not expect_directory:
                if stat.S_ISDIR(expected.st_mode):
                    raise IsADirectoryError(f"not a regular file: {path!r}")
                if not stat.S_ISREG(expected.st_mode):
                    raise MRSHwError(f"not a regular file: {path!r}")

            try:
                opened = os.open(
                    component,
                    _secure_open_flags(directory=expect_directory),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise MRSHwError(
                    f"path component changed while opening: {component!r}"
                ) from exc
            try:
                attributes = os.fstat(opened)
                expected_type = stat.S_ISDIR if expect_directory else stat.S_ISREG
                if not expected_type(attributes.st_mode):
                    raise MRSHwError(
                        f"path component changed type: {component!r}"
                    )
                if _identity(attributes) != _identity(expected):
                    raise MRSHwError(
                        f"path component changed identity: {component!r}"
                    )
            except BaseException:
                os.close(opened)
                raise
            os.close(descriptor)
            descriptor = opened
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_scanned_directory(
    root_descriptor: int,
    parts: _Parts,
    identities: Dict[_Parts, _Identity],
) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        if _identity(os.fstat(descriptor)) != identities[()]:
            raise MRSHwError("scanned root directory changed identity")
        prefix: _Parts = ()
        for component in parts:
            if not component or component in (".", "..") or "/" in component:
                raise MRSHwError("directory scan produced an unsafe path component")
            prefix += (component,)
            try:
                opened = os.open(
                    component,
                    _secure_open_flags(directory=True),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise MRSHwError(
                    f"scanned directory component changed: {component!r}"
                ) from exc
            try:
                attributes = os.fstat(opened)
                if not stat.S_ISDIR(attributes.st_mode):
                    raise MRSHwError("scanned directory was replaced by a non-directory")
                if _identity(attributes) != identities[prefix]:
                    raise MRSHwError("scanned directory changed identity")
            except BaseException:
                os.close(opened)
                raise
            os.close(descriptor)
            descriptor = opened
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_scanned_file(
    root_descriptor: int,
    parts: _Parts,
    directory_identities: Dict[_Parts, _Identity],
    expected_identity: _Identity,
) -> int:
    if not parts:
        raise MRSHwError("directory scan produced an empty file path")
    parent = _open_scanned_directory(
        root_descriptor, parts[:-1], directory_identities
    )
    try:
        name = parts[-1]
        if not name or name in (".", "..") or "/" in name:
            raise MRSHwError("directory scan produced an unsafe file name")
        try:
            descriptor = os.open(
                name,
                _secure_open_flags(directory=False),
                dir_fd=parent,
            )
        except OSError as exc:
            raise MRSHwError(f"scanned file changed: {name!r}") from exc
    finally:
        os.close(parent)
    try:
        attributes = os.fstat(descriptor)
        if not stat.S_ISREG(attributes.st_mode):
            raise MRSHwError("scanned file was replaced by a non-regular file")
        if _identity(attributes) != expected_identity:
            raise MRSHwError("scanned file changed identity")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_batch_file(path: Path) -> int:
    """Open one explicit file without trusting any pathname component twice."""
    return _open_explicit_path_no_follow(path, directory=False)


def scan_directory(
    directory: Union[str, os.PathLike[str]],
    extensions: Optional[Iterable[str]] = None,
    recursive: bool = True,
) -> FingerprintList:
    """Fingerprint regular files in deterministic path order.

    Symlinks are skipped so a scan cannot unexpectedly escape the requested
    directory. The returned list owns native resources and can be used as a
    context manager.
    """
    if not isinstance(recursive, bool):
        raise TypeError("recursive must be a boolean")
    root = Path(_bounded_path_text(directory))
    try:
        expected_root = root.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"directory not found: {root!r}") from exc
    if stat.S_ISLNK(expected_root.st_mode):
        raise ValueError(f"directory symlinks are not scanned: {root!r}")
    if not stat.S_ISDIR(expected_root.st_mode):
        raise NotADirectoryError(f"not a directory: {root!r}")
    allowed = _normalized_extensions(extensions)
    root_descriptor = _open_explicit_path_no_follow(root, directory=True)
    try:
        fingerprints = FingerprintList()
    except BaseException:
        os.close(root_descriptor)
        raise
    try:
        opened_root = os.fstat(root_descriptor)
        if _identity(opened_root) != _identity(expected_root):
            raise MRSHwError("directory changed identity while the scan started")
        directory_identities: Dict[_Parts, _Identity] = {
            (): _identity(opened_root)
        }
        directories: List[Tuple[_Parts, int]] = [((), 0)]
        files: List[Tuple[_Parts, _Identity]] = []
        visited_entries = 0
        stored_path_bytes = 1
        directory_index = 0

        while directory_index < len(directories):
            parts, depth = directories[directory_index]
            directory_index += 1
            descriptor = _open_scanned_directory(
                root_descriptor, parts, directory_identities
            )
            try:
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        name = entry.name
                        if not name or name in (".", "..") or "/" in name:
                            raise MRSHwError(
                                "directory scan produced an unsafe path component"
                            )
                        if visited_entries >= _MAX_SCAN_ENTRIES:
                            raise MRSHwError(
                                f"directory scan exceeds the {_MAX_SCAN_ENTRIES}-entry limit"
                            )
                        visited_entries += 1
                        try:
                            attributes = os.stat(
                                name, dir_fd=descriptor, follow_symlinks=False
                            )
                        except OSError as exc:
                            raise MRSHwError(
                                f"directory entry changed during scan: {name!r}"
                            ) from exc
                        child_parts = parts + (name,)
                        relative_label = "/".join(child_parts)
                        path_bytes = len(os.fsencode(relative_label)) + 1
                        if path_bytes > _MAX_SCAN_PATH_BYTES - stored_path_bytes:
                            raise MRSHwError("directory scan path data exceeds its limit")
                        stored_path_bytes += path_bytes

                        if stat.S_ISREG(attributes.st_mode):
                            if allowed is not None and Path(name).suffix.lower() not in allowed:
                                continue
                            files.append((child_parts, _identity(attributes)))
                        elif recursive and stat.S_ISDIR(attributes.st_mode):
                            if depth >= _MAX_SCAN_DEPTH:
                                raise MRSHwError(
                                    f"directory scan exceeds the {_MAX_SCAN_DEPTH}-level limit"
                                )
                            directory_identities[child_parts] = _identity(attributes)
                            directories.append((child_parts, depth + 1))
            finally:
                os.close(descriptor)

        for parts, expected_identity in sorted(files, key=lambda item: "/".join(item[0])):
            descriptor = _open_scanned_file(
                root_descriptor,
                parts,
                directory_identities,
                expected_identity,
            )
            try:
                fingerprints._add_open_fd(descriptor, "/".join(parts))
            finally:
                os.close(descriptor)
        return fingerprints
    except BaseException:
        fingerprints.close()
        raise
    finally:
        os.close(root_descriptor)


def batch_compare(
    files: Iterable[Union[str, os.PathLike[str]]], threshold: int = 50
) -> List[Comparison]:
    """Compare a bounded batch of securely opened regular files."""
    threshold = _validate_threshold(threshold)
    with FingerprintList() as fingerprints:
        for index, value in enumerate(files):
            if index >= _MAX_LIST_ENTRIES:
                raise MRSHwError(
                    f"batch exceeds the {_MAX_LIST_ENTRIES}-file limit"
                )
            path = Path(_bounded_path_text(value))
            descriptor = _open_batch_file(path)
            try:
                fingerprints._add_open_fd(descriptor, path.name)
            finally:
                os.close(descriptor)
        return fingerprints.compare_all(threshold)
