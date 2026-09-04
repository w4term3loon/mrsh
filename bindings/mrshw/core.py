"""Safe, ownership-aware Python bindings for MRSH-v2."""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib.resources
import os
import threading
from collections import namedtuple
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Union


class MRSHwException(Exception):
    """Base exception for the package."""


class MRSHwError(MRSHwException):
    """Raised when a native MRSH operation fails."""


class MRSHwDigestError(MRSHwError, ValueError):
    """Raised when a serialized MRSH fingerprint is malformed."""


Metadata = namedtuple("Metadata", ["name", "size", "filters"])
Comparison = namedtuple("Comparison", ["hash1", "hash2", "score"])


def _is_library_name(name: str) -> bool:
    lowered = name.lower()
    return (
        name.startswith("libmrsh")
        and (
            ".so" in lowered
            or lowered.endswith((".dylib", ".dll", ".pyd"))
        )
    ) or (name.startswith("mrsh") and lowered.endswith((".dll", ".pyd")))


def _load_library() -> ctypes.CDLL:
    """Load the bundled native library without relying on the working directory."""
    failures = []
    override = os.environ.get("MRSHW_LIBRARY")
    if override:
        try:
            return ctypes.CDLL(os.path.abspath(os.path.expanduser(override)))
        except OSError as exc:
            raise MRSHwError(
                f"Could not load the MRSH native library from MRSHW_LIBRARY={override!r}: "
                f"{exc}"
            ) from exc

    try:
        package_root = importlib.resources.files(__package__)
        resources = sorted(
            (item for item in package_root.iterdir() if _is_library_name(item.name)),
            key=lambda item: (item.name == "libmrsh.so", item.name),
        )
        for resource in resources:
            try:
                with importlib.resources.as_file(resource) as library_path:
                    return ctypes.CDLL(str(library_path))
            except (OSError, TypeError) as exc:
                failures.append(str(exc))
    except (AttributeError, FileNotFoundError, ModuleNotFoundError, TypeError):
        pass

    # Editable/local builds may place the library beside the Python package.
    package_directory = Path(__file__).resolve().parent
    local_candidates = sorted(
        (
            candidate
            for directory in (package_directory, package_directory / "lib")
            if directory.is_dir()
            for candidate in directory.iterdir()
            if candidate.is_file() and _is_library_name(candidate.name)
        ),
        key=lambda item: (item.name == "libmrsh.so", item.name),
    )
    for candidate in local_candidates:
        try:
            return ctypes.CDLL(str(candidate))
        except OSError as exc:
            failures.append(str(exc))

    system_library = ctypes.util.find_library("mrsh")
    if system_library:
        try:
            return ctypes.CDLL(system_library)
        except OSError as exc:
            failures.append(str(exc))

    detail = f" Last loader error: {failures[-1]}" if failures else ""
    raise MRSHwError(
        "Could not load the MRSH native library. Reinstall mrshw or set "
        f"MRSHW_LIBRARY to an explicit library path.{detail}"
    )


lib = _load_library()


def _setup_library_functions() -> None:
    """Declare only opaque pointer types at the Python/native boundary."""
    pointer = ctypes.c_void_p

    lib.mrsh_abi_version.restype = ctypes.c_int
    lib.mrsh_abi_version.argtypes = []
    lib.mrsh_error_string.restype = ctypes.c_char_p
    lib.mrsh_error_string.argtypes = [ctypes.c_int]
    lib.fp_name_capacity.restype = ctypes.c_size_t
    lib.fp_name_capacity.argtypes = []
    lib.fp_max_digest_size.restype = ctypes.c_size_t
    lib.fp_max_digest_size.argtypes = []
    lib.fpl_max_digest_size.restype = ctypes.c_size_t
    lib.fpl_max_digest_size.argtypes = []
    lib.fpl_max_entries.restype = ctypes.c_size_t
    lib.fpl_max_entries.argtypes = []
    lib.scan_max_entries.restype = ctypes.c_size_t
    lib.scan_max_entries.argtypes = []
    lib.scan_max_path_bytes.restype = ctypes.c_size_t
    lib.scan_max_path_bytes.argtypes = []
    lib.scan_max_depth.restype = ctypes.c_uint
    lib.scan_max_depth.argtypes = []

    lib.fp_init.restype = pointer
    lib.fp_init.argtypes = []
    lib.fp_destroy.restype = None
    lib.fp_destroy.argtypes = [pointer]
    lib.fp_add_file.restype = ctypes.c_int
    lib.fp_add_file.argtypes = [pointer, ctypes.c_char_p, ctypes.c_char_p]
    lib.fp_add_bytes.restype = ctypes.c_int
    lib.fp_add_bytes.argtypes = [pointer, pointer, ctypes.c_size_t, ctypes.c_char_p]
    lib.fp_clone.restype = pointer
    lib.fp_clone.argtypes = [pointer]
    lib.fp_parse.restype = ctypes.c_int
    lib.fp_parse.argtypes = [ctypes.c_char_p, ctypes.POINTER(pointer)]
    lib.fp_metadata.restype = ctypes.c_int
    lib.fp_metadata.argtypes = [
        pointer,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.fp_compare.restype = ctypes.c_int
    lib.fp_compare.argtypes = [pointer, pointer]
    lib.fp_str.restype = pointer
    lib.fp_str.argtypes = [pointer]

    lib.fpl_init.restype = pointer
    lib.fpl_init.argtypes = []
    lib.fpl_destroy.restype = None
    lib.fpl_destroy.argtypes = [pointer]
    lib.fpl_clone.restype = pointer
    lib.fpl_clone.argtypes = [pointer]
    lib.fpl_parse.restype = ctypes.c_int
    lib.fpl_parse.argtypes = [ctypes.c_char_p, ctypes.POINTER(pointer)]
    lib.fpl_size.restype = ctypes.c_size_t
    lib.fpl_size.argtypes = [pointer]
    lib.fpl_add_path_ex.restype = ctypes.c_int
    lib.fpl_add_path_ex.argtypes = [
        pointer,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.fpl_add_path_no_follow.restype = ctypes.c_int
    lib.fpl_add_path_no_follow.argtypes = [
        pointer,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    lib.fpl_add_fd.restype = ctypes.c_int
    lib.fpl_add_fd.argtypes = [pointer, ctypes.c_int, ctypes.c_char_p]
    lib.fpl_add_bytes.restype = ctypes.c_int
    lib.fpl_add_bytes.argtypes = [pointer, pointer, ctypes.c_size_t, ctypes.c_char_p]
    lib.fpl_str.restype = pointer
    lib.fpl_str.argtypes = [pointer]

    lib.cl_fpl_all.restype = pointer
    lib.cl_fpl_all.argtypes = [pointer, ctypes.c_uint]
    lib.cl_fpl_vs_fpl.restype = pointer
    lib.cl_fpl_vs_fpl.argtypes = [pointer, pointer, ctypes.c_uint]
    lib.cl_fp_vs_fpl.restype = pointer
    lib.cl_fp_vs_fpl.argtypes = [pointer, pointer, ctypes.c_uint]
    lib.cl_size.restype = ctypes.c_size_t
    lib.cl_size.argtypes = [pointer]
    lib.cl_get.restype = ctypes.c_int
    lib.cl_get.argtypes = [
        pointer,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.cl_free.restype = None
    lib.cl_free.argtypes = [pointer]

    lib.str_free.restype = None
    lib.str_free.argtypes = [pointer]
    lib.str_compare.restype = ctypes.c_int
    lib.str_compare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]


try:
    _setup_library_functions()
except AttributeError as exc:
    raise MRSHwError(f"The loaded MRSH library has an incompatible ABI: {exc}") from exc

if lib.mrsh_abi_version() != 2:
    raise MRSHwError("The loaded MRSH library has an unsupported ABI version")

_NAME_CAPACITY = int(lib.fp_name_capacity())
_MAX_FINGERPRINT_DIGEST_BYTES = int(lib.fp_max_digest_size())
_MAX_LIST_DIGEST_BYTES = int(lib.fpl_max_digest_size())
_MAX_LIST_ENTRIES = int(lib.fpl_max_entries())
_MAX_SCAN_ENTRIES = int(lib.scan_max_entries())
_MAX_SCAN_PATH_BYTES = int(lib.scan_max_path_bytes())
_MAX_SCAN_DEPTH = int(lib.scan_max_depth())
_MRSH_ERR_NOMEM = -2
_MAX_PATH_BYTES = _NAME_CAPACITY - 1
_MAX_INPUT_NESTING = 256
_MAX_INPUT_NODES = 2 * _MAX_LIST_ENTRIES + 1


def _error_text(status: int) -> str:
    raw = lib.mrsh_error_string(status)
    return raw.decode("utf-8", errors="replace") if raw else f"error {status}"


def _check_status(status: int, operation: str, *, digest: bool = False) -> None:
    if status == 0:
        return
    exception = MRSHwDigestError if digest and status != _MRSH_ERR_NOMEM else MRSHwError
    raise exception(f"{operation} failed: {_error_text(status)} (error {status})")


def _validate_threshold(threshold: int) -> int:
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("threshold must be an integer")
    if not 0 <= threshold <= 100:
        raise ValueError("threshold must be between 0 and 100 inclusive")
    return threshold


def _contains_ascii_control(encoded: bytes) -> bool:
    return any(byte < 0x20 or byte == 0x7F for byte in encoded)


def _encode_label(label: str) -> bytes:
    if not isinstance(label, str):
        raise TypeError("label must be a string")
    if len(label) >= _NAME_CAPACITY:
        raise ValueError(f"label must be shorter than {_NAME_CAPACITY} characters")
    try:
        encoded = label.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("label contains a character that cannot be encoded") from exc
    if len(encoded) >= _NAME_CAPACITY:
        raise ValueError(f"label must be shorter than {_NAME_CAPACITY} UTF-8 bytes")
    if _contains_ascii_control(encoded):
        raise ValueError("label cannot contain ASCII control characters")
    return encoded


def _encode_filesystem_label(label: str) -> bytes:
    if not isinstance(label, str):
        raise TypeError("label must be a string")
    if len(label) >= _NAME_CAPACITY:
        raise ValueError(f"label must be shorter than {_NAME_CAPACITY} characters")
    try:
        encoded = label.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError as exc:
        raise ValueError("filesystem label contains an unencodable character") from exc
    if len(encoded) >= _NAME_CAPACITY:
        raise ValueError(
            f"label must be shorter than {_NAME_CAPACITY} filesystem bytes"
        )
    if _contains_ascii_control(encoded):
        raise ValueError("label cannot contain ASCII control characters")
    return encoded


def _encode_path(path: Union[str, os.PathLike[str]]) -> bytes:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or os.PathLike object")
    raw_path = os.fspath(path)
    if len(raw_path) > _MAX_PATH_BYTES:
        raise ValueError(f"path exceeds the {_MAX_PATH_BYTES}-byte limit")
    encoded = os.fsencode(raw_path)
    if len(encoded) > _MAX_PATH_BYTES:
        raise ValueError(f"path exceeds the {_MAX_PATH_BYTES}-byte limit")
    if b"\0" in encoded:
        raise ValueError("path cannot contain a NUL byte")
    return encoded


def _encode_digest(
    digest: str, maximum_bytes: int = _MAX_FINGERPRINT_DIGEST_BYTES
) -> bytes:
    if not isinstance(digest, str):
        raise TypeError("digest must be a string")
    if "\0" in digest:
        raise MRSHwDigestError("fingerprint digest cannot contain a NUL character")
    if len(digest) > maximum_bytes:
        raise MRSHwDigestError(
            f"fingerprint digest exceeds the {maximum_bytes}-byte limit"
        )
    try:
        encoded = digest.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError as exc:
        raise MRSHwDigestError(
            "fingerprint digest contains a character that cannot be encoded"
        ) from exc
    if len(encoded) > maximum_bytes:
        raise MRSHwDigestError(
            f"fingerprint digest exceeds the {maximum_bytes}-byte limit"
        )
    return encoded


def _encode_list_digest(digest: str) -> bytes:
    encoded = _encode_digest(digest, _MAX_LIST_DIGEST_BYTES)
    entries = 0 if not digest else digest.count("\n") + (not digest.endswith("\n"))
    if entries > _MAX_LIST_ENTRIES:
        raise MRSHwDigestError(
            f"fingerprint list exceeds the {_MAX_LIST_ENTRIES}-entry limit"
        )
    return encoded


def _as_buffer(data: Union[bytes, bytearray, memoryview]) -> Tuple[bytes, ctypes.c_char_p]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"unsupported binary data type: {type(data)!r}")
    value = bytes(data)
    return value, ctypes.c_char_p(value)


@contextmanager
def _locked(*objects: object) -> Iterator[None]:
    unique = {id(obj): obj for obj in objects}
    ordered = [unique[key] for key in sorted(unique)]
    for obj in ordered:
        obj._lock.acquire()  # type: ignore[attr-defined]
    try:
        yield
    finally:
        for obj in reversed(ordered):
            obj._lock.release()  # type: ignore[attr-defined]


def _decode_name(value: Optional[bytes]) -> str:
    return os.fsdecode(value or b"")


def _comparisons_from_native(pointer: int) -> List[Comparison]:
    if not pointer:
        raise MRSHwError("comparison failed: native allocation or validation error")
    try:
        results = []
        for index in range(lib.cl_size(pointer)):
            name1 = ctypes.c_char_p()
            name2 = ctypes.c_char_p()
            score = ctypes.c_uint8()
            status = lib.cl_get(
                pointer,
                index,
                ctypes.byref(name1),
                ctypes.byref(name2),
                ctypes.byref(score),
            )
            _check_status(status, "reading comparison result")
            results.append(
                Comparison(_decode_name(name1.value), _decode_name(name2.value), score.value)
            )
        return results
    finally:
        lib.cl_free(pointer)


class Fingerprint:
    """An owned MRSH fingerprint. Similarity scores range from 0 to 100."""

    def __init__(
        self,
        data: Optional[
            Union[
                str,
                os.PathLike[str],
                bytes,
                bytearray,
                memoryview,
                Tuple[Union[str, os.PathLike[str], bytes, bytearray, memoryview], str],
            ]
        ] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._fp = lib.fp_init()
        if not self._fp:
            raise MRSHwError("failed to allocate a fingerprint")
        try:
            if data is not None:
                self.update(data)
        except BaseException:
            self.close()
            raise

    @classmethod
    def _from_pointer(cls, pointer: int) -> "Fingerprint":
        try:
            instance = cls.__new__(cls)
            instance._lock = threading.RLock()
            instance._fp = pointer
            return instance
        except BaseException:
            lib.fp_destroy(pointer)
            raise

    @classmethod
    def from_digest(cls, digest: str) -> "Fingerprint":
        """Construct an independently owned fingerprint from a canonical digest."""
        output = ctypes.c_void_p()
        status = lib.fp_parse(_encode_digest(digest), ctypes.byref(output))
        _check_status(status, "parsing fingerprint", digest=True)
        if not output.value:
            raise MRSHwError("parsing fingerprint returned no native object")
        return cls._from_pointer(output.value)

    @property
    def closed(self) -> bool:
        with self._lock:
            return not bool(self._fp)

    def _ensure_open(self) -> None:
        if not self._fp:
            raise MRSHwError("fingerprint is closed")

    @staticmethod
    def _populate(pointer: int, data: object) -> None:
        label_bytes: Optional[bytes] = None
        value = data
        if isinstance(data, tuple):
            if len(data) != 2:
                raise TypeError("a labeled fingerprint must be a (data, label) pair")
            value, label = data
            label_bytes = _encode_label(label)

        if isinstance(value, (str, os.PathLike)):
            path_bytes = _encode_path(value)
            if label_bytes is None:
                # A path is also the default serialized label, so validate the
                # bounded native name field before entering C.
                if len(path_bytes) >= _NAME_CAPACITY:
                    raise ValueError(
                        f"path label must be shorter than {_NAME_CAPACITY} filesystem bytes; "
                        "supply an explicit shorter label"
                    )
                if _contains_ascii_control(path_bytes):
                    raise ValueError(
                        "path used as a label cannot contain ASCII control characters"
                    )
            status = lib.fp_add_file(pointer, path_bytes, label_bytes)
            _check_status(status, f"hashing file {os.fspath(value)!r}")
            return

        if isinstance(value, (bytes, bytearray, memoryview)):
            binary, buffer = _as_buffer(value)
            status = lib.fp_add_bytes(
                pointer,
                ctypes.cast(buffer, ctypes.c_void_p),
                len(binary),
                label_bytes if label_bytes is not None else b"n/a",
            )
            _check_status(status, "hashing bytes")
            return
        raise TypeError(f"unsupported fingerprint data type: {type(value)!r}")

    def update(self, data: object) -> "Fingerprint":
        """Atomically replace this fingerprint with one generated from *data*."""
        with self._lock:
            self._ensure_open()
            replacement = lib.fp_init()
            if not replacement:
                raise MRSHwError("failed to allocate a replacement fingerprint")
            try:
                self._populate(replacement, data)
            except BaseException:
                lib.fp_destroy(replacement)
                raise
            previous = self._fp
            self._fp = replacement
            lib.fp_destroy(previous)
        return self

    def close(self) -> None:
        """Release native ownership. Calling close repeatedly is safe."""
        lock = getattr(self, "_lock", None)
        if lock is None:
            return
        with lock:
            pointer = getattr(self, "_fp", None)
            self._fp = None
            if pointer:
                lib.fp_destroy(pointer)

    def __enter__(self) -> "Fingerprint":
        with self._lock:
            self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self) -> "Fingerprint":
        with self._lock:
            self._ensure_open()
            pointer = lib.fp_clone(self._fp)
            if not pointer:
                raise MRSHwError("failed to clone fingerprint")
        return type(self)._from_pointer(pointer)

    def __deepcopy__(self, memo: dict) -> "Fingerprint":
        clone = self.__copy__()
        memo[id(self)] = clone
        return clone

    def __reduce__(self):
        return (_restore_fingerprint, (self.hexdigest(),))

    def hexdigest(self) -> str:
        with self._lock:
            self._ensure_open()
            raw = lib.fp_str(self._fp)
            if not raw:
                raise MRSHwError("serializing fingerprint failed")
            try:
                return ctypes.string_at(raw).decode("utf-8", errors="surrogateescape")
            finally:
                lib.str_free(raw)

    def metadata(self) -> Metadata:
        with self._lock:
            self._ensure_open()
            name = ctypes.c_char_p()
            size = ctypes.c_uint64()
            filters = ctypes.c_uint32()
            status = lib.fp_metadata(
                self._fp,
                ctypes.byref(name),
                ctypes.byref(size),
                ctypes.byref(filters),
            )
            _check_status(status, "reading fingerprint metadata")
            return Metadata(_decode_name(name.value), size.value, filters.value)

    def compare(self, other: "Fingerprint") -> int:
        if not isinstance(other, Fingerprint):
            raise TypeError("other must be a Fingerprint")
        with _locked(self, other):
            self._ensure_open()
            other._ensure_open()
            score = lib.fp_compare(self._fp, other._fp)
            _check_status(score if score < 0 else 0, "comparing fingerprints")
            return score

    def __str__(self) -> str:
        return self.hexdigest()

    def __repr__(self) -> str:
        if self.closed:
            return "Fingerprint(closed=True)"
        metadata = self.metadata()
        return (
            f"Fingerprint(name={metadata.name!r}, size={metadata.size}, "
            f"filters={metadata.filters})"
        )


class FingerprintList:
    """An owned collection of MRSH fingerprints."""

    def __init__(self, data: Optional[object] = None) -> None:
        self._lock = threading.RLock()
        self._fpl = lib.fpl_init()
        if not self._fpl:
            raise MRSHwError("failed to allocate a fingerprint list")
        try:
            if data is not None:
                self.add(data)
        except BaseException:
            self.close()
            raise

    @classmethod
    def _from_pointer(cls, pointer: int) -> "FingerprintList":
        try:
            instance = cls.__new__(cls)
            instance._lock = threading.RLock()
            instance._fpl = pointer
            return instance
        except BaseException:
            lib.fpl_destroy(pointer)
            raise

    @classmethod
    def from_digest(cls, digest: str) -> "FingerprintList":
        output = ctypes.c_void_p()
        status = lib.fpl_parse(_encode_list_digest(digest), ctypes.byref(output))
        _check_status(status, "parsing fingerprint list", digest=True)
        if not output.value:
            raise MRSHwError("parsing fingerprint list returned no native object")
        return cls._from_pointer(output.value)

    @property
    def closed(self) -> bool:
        with self._lock:
            return not bool(self._fpl)

    def _ensure_open(self) -> None:
        if not self._fpl:
            raise MRSHwError("fingerprint list is closed")

    @staticmethod
    def _is_labeled_item(data: object) -> bool:
        return (
            isinstance(data, tuple)
            and len(data) == 2
            and isinstance(data[1], str)
        )

    @classmethod
    def _add_one_to_pointer(cls, pointer: int, data: object, recursive: bool) -> None:
        if cls._is_labeled_item(data):
            value, label = data
            label_bytes = _encode_label(label)
        else:
            value = data
            label_bytes = None

        if isinstance(value, (str, os.PathLike)):
            path_bytes = _encode_path(value)
            status = lib.fpl_add_path_ex(pointer, path_bytes, label_bytes, int(recursive))
            _check_status(status, f"adding path {os.fspath(value)!r}")
            return
        if isinstance(value, (bytes, bytearray, memoryview)):
            binary, buffer = _as_buffer(value)
            status = lib.fpl_add_bytes(
                pointer,
                ctypes.cast(buffer, ctypes.c_void_p),
                len(binary),
                label_bytes if label_bytes is not None else b"n/a",
            )
            _check_status(status, "adding bytes")
            return
        raise TypeError(f"unsupported fingerprint-list input type: {type(value)!r}")

    @classmethod
    def _add_to_pointer(cls, pointer: int, data: object, recursive: bool) -> None:
        """Add bounded structured input without recursive Python calls."""
        # Exit markers distinguish active ancestors from harmless shared
        # containers, so cycles are rejected without changing duplicate-input
        # semantics. Counting scheduled nodes also bounds compact shared DAGs.
        stack = [(True, data, 0)]
        active_containers: set[int] = set()
        scheduled_nodes = 1

        while stack:
            entering, value, depth = stack.pop()
            if not entering:
                active_containers.remove(id(value))
                continue

            if cls._is_labeled_item(value) or not isinstance(value, (list, tuple)):
                cls._add_one_to_pointer(pointer, value, recursive)
                continue

            if depth >= _MAX_INPUT_NESTING:
                raise ValueError(
                    f"fingerprint-list input exceeds the {_MAX_INPUT_NESTING}-level "
                    "nesting limit"
                )
            identity = id(value)
            if identity in active_containers:
                raise ValueError("fingerprint-list input contains a container cycle")
            child_count = len(value)
            if child_count > _MAX_INPUT_NODES - scheduled_nodes:
                raise ValueError(
                    f"fingerprint-list input exceeds the {_MAX_INPUT_NODES}-node limit"
                )
            scheduled_nodes += child_count
            active_containers.add(identity)
            stack.append((False, value, depth))
            for child in reversed(value):
                stack.append((True, child, depth + 1))

    def add(self, data: object, *, recursive: bool = False) -> "FingerprintList":
        """Atomically add one item or a nested list of items."""
        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")
        with self._lock:
            self._ensure_open()
            if not isinstance(data, (list, tuple)) or self._is_labeled_item(data):
                # Each native single-item insertion is itself transactional.
                self._add_to_pointer(self._fpl, data, recursive)
                return self
            replacement = lib.fpl_clone(self._fpl)
            if not replacement:
                raise MRSHwError("failed to clone fingerprint list for update")
            try:
                self._add_to_pointer(replacement, data, recursive)
            except BaseException:
                lib.fpl_destroy(replacement)
                raise
            previous = self._fpl
            self._fpl = replacement
            lib.fpl_destroy(previous)
        return self

    def _add_regular_path_no_follow(
        self, path: Union[str, os.PathLike[str]], label: str
    ) -> None:
        """Add one already-enumerated regular path without following symlinks."""
        path_bytes = _encode_path(path)
        label_bytes = _encode_filesystem_label(label)
        with self._lock:
            self._ensure_open()
            status = lib.fpl_add_path_no_follow(
                self._fpl, path_bytes, label_bytes
            )
            _check_status(status, f"adding scanned path {os.fspath(path)!r}")

    def _add_open_fd(self, descriptor: int, label: str) -> None:
        """Hash one borrowed regular descriptor without changing its offset."""
        if isinstance(descriptor, bool) or not isinstance(descriptor, int):
            raise TypeError("descriptor must be an integer")
        if descriptor < 0:
            raise ValueError("descriptor must be non-negative")
        label_bytes = _encode_filesystem_label(label)
        with self._lock:
            self._ensure_open()
            status = lib.fpl_add_fd(self._fpl, descriptor, label_bytes)
            _check_status(status, f"hashing open descriptor for {label!r}")

    def __iadd__(self, other: object) -> "FingerprintList":
        return self.add(other)

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        if lock is None:
            return
        with lock:
            pointer = getattr(self, "_fpl", None)
            self._fpl = None
            if pointer:
                lib.fpl_destroy(pointer)

    def __enter__(self) -> "FingerprintList":
        with self._lock:
            self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self) -> "FingerprintList":
        with self._lock:
            self._ensure_open()
            pointer = lib.fpl_clone(self._fpl)
            if not pointer:
                raise MRSHwError("failed to clone fingerprint list")
        return type(self)._from_pointer(pointer)

    def __deepcopy__(self, memo: dict) -> "FingerprintList":
        clone = self.__copy__()
        memo[id(self)] = clone
        return clone

    def __reduce__(self):
        return (_restore_fingerprint_list, (self.hexdigest(),))

    def __len__(self) -> int:
        with self._lock:
            self._ensure_open()
            return int(lib.fpl_size(self._fpl))

    def hexdigest(self) -> str:
        with self._lock:
            self._ensure_open()
            raw = lib.fpl_str(self._fpl)
            if not raw:
                raise MRSHwError("serializing fingerprint list failed")
            try:
                return ctypes.string_at(raw).decode("utf-8", errors="surrogateescape")
            finally:
                lib.str_free(raw)

    def compare_all(self, threshold: int = 0) -> List[Comparison]:
        threshold = _validate_threshold(threshold)
        with self._lock:
            self._ensure_open()
            pointer = lib.cl_fpl_all(self._fpl, threshold)
            return _comparisons_from_native(pointer)

    def compare_with(
        self, other: Union[Fingerprint, "FingerprintList"], threshold: int = 0
    ) -> List[Comparison]:
        threshold = _validate_threshold(threshold)
        if not isinstance(other, (Fingerprint, FingerprintList)):
            raise TypeError("other must be a Fingerprint or FingerprintList")
        with _locked(self, other):
            self._ensure_open()
            other._ensure_open()
            if isinstance(other, Fingerprint):
                pointer = lib.cl_fp_vs_fpl(other._fp, self._fpl, threshold)
            else:
                pointer = lib.cl_fpl_vs_fpl(self._fpl, other._fpl, threshold)
            return _comparisons_from_native(pointer)

    def __str__(self) -> str:
        return self.hexdigest()

    def __repr__(self) -> str:
        if self.closed:
            return "FingerprintList(closed=True)"
        return f"FingerprintList(size={len(self)})"


def _restore_fingerprint(digest: str) -> Fingerprint:
    return Fingerprint.from_digest(digest)


def _restore_fingerprint_list(digest: str) -> FingerprintList:
    return FingerprintList.from_digest(digest)


def hash(data: object) -> str:
    """Generate a canonical MRSH fingerprint string."""
    with Fingerprint(data) as fingerprint:
        return fingerprint.hexdigest()


def compare(
    entity1: Union[Fingerprint, FingerprintList, str],
    entity2: Union[Fingerprint, FingerprintList, str],
    threshold: int = 0,
) -> Union[int, List[Comparison]]:
    """Compare two compatible entities using 0..100 similarity scores."""
    threshold = _validate_threshold(threshold)
    if isinstance(entity1, str) and isinstance(entity2, str):
        return diff(entity1, entity2)
    if isinstance(entity1, Fingerprint) and isinstance(entity2, Fingerprint):
        return entity1.compare(entity2)
    if isinstance(entity1, Fingerprint) and isinstance(entity2, FingerprintList):
        return entity2.compare_with(entity1, threshold)
    if isinstance(entity1, FingerprintList) and isinstance(
        entity2, (Fingerprint, FingerprintList)
    ):
        return entity1.compare_with(entity2, threshold)
    raise TypeError("unsupported comparison types")


def diff(digest1: str, digest2: str) -> int:
    """Return the 0..100 similarity score of two canonical digest strings."""
    score = lib.str_compare(_encode_digest(digest1), _encode_digest(digest2))
    if score < 0:
        _check_status(score, "comparing fingerprint digests", digest=True)
    return score
