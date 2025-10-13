"""
Core MRSHw functionality and classes.
"""

import os
import ctypes
from collections import namedtuple
from typing import Union, List, Tuple, Optional
import importlib.resources


class MRSHwException(Exception):
    """Base exception class for MRSHw errors."""
    pass


class MRSHwError(MRSHwException):
    """Raised when MRSHw operations fail."""
    pass


# Load the shared library
def _load_library():
    lib_name = "libmrsh.so"
    try:
        # Python 3.9+: returns a pathlib.Path
        lib_path = importlib.resources.files(__package__).joinpath(lib_name)
        return ctypes.CDLL(str(lib_path))
    except Exception:
        # Fallbacks if needed
        for path in (
            os.path.join(os.path.dirname(__file__), lib_name),
            os.path.join(os.path.dirname(__file__), "lib", lib_name),
            lib_name,
        ):
            try:
                return ctypes.CDLL(path)
            except OSError:
                pass
    raise MRSHwError(f"Could not load {lib_name}. Please ensure it's installed correctly.")

lib = _load_library()


# C structure definitions
class _CFingerprint(ctypes.Structure):
    """Internal C fingerprint structure."""
    pass

_CFingerprint._fields_ = [
    ("bf_list", ctypes.c_void_p),
    ("bf_list_last_element", ctypes.c_void_p),
    ("next", ctypes.POINTER(_CFingerprint)),
    ("amount_of_BF", ctypes.c_uint32),
    ("file_name", ctypes.c_char * 200),
    ("filesize", ctypes.c_uint32),
]


class _CFingerprintList(ctypes.Structure):
    """Internal C fingerprint list structure."""
    _fields_ = [
        ("list", ctypes.POINTER(_CFingerprint)),
        ("last_element", ctypes.POINTER(_CFingerprint)),
        ("size", ctypes.c_long)
    ]


class _CCompare(ctypes.Structure):
    """Internal C comparison structure."""
    _fields_ = [
        ("name1", ctypes.c_char_p),
        ("name2", ctypes.c_char_p),
        ("score", ctypes.c_uint8)
    ]


class _CCompareList(ctypes.Structure):
    """Internal C comparison list structure."""
    _fields_ = [
        ("list", ctypes.POINTER(_CCompare)),
        ("size", ctypes.c_long)
    ]


# Named tuples for return values
Metadata = namedtuple('Metadata', ['name', 'size', 'filters'])
Comparison = namedtuple('Comparison', ['hash1', 'hash2', 'score'])


# Function signature definitions
def _setup_library_functions():
    """Setup C library function signatures."""

    # Fingerprint functions
    lib.fp_init.restype = ctypes.POINTER(_CFingerprint)
    lib.fp_init.argtypes = []

    lib.fp_destroy.restype = None
    lib.fp_destroy.argtypes = [ctypes.POINTER(_CFingerprint)]

    lib.fp_add_file.restype = ctypes.c_int32
    lib.fp_add_file.argtypes = [ctypes.POINTER(_CFingerprint), ctypes.c_char_p, ctypes.c_char_p]

    lib.fp_add_bytes.restype = ctypes.c_int32
    lib.fp_add_bytes.argtypes = [ctypes.POINTER(_CFingerprint), ctypes.c_char_p, ctypes.c_ulong,
                                 ctypes.c_char_p]

    lib.fp_compare.restype = ctypes.c_uint8
    lib.fp_compare.argtypes = [ctypes.POINTER(_CFingerprint), ctypes.POINTER(_CFingerprint)]

    lib.fp_str.restype = ctypes.c_void_p
    lib.fp_str.argtypes = [ctypes.POINTER(_CFingerprint)]

    # FingerprintList functions
    lib.fpl_init.restype = ctypes.POINTER(_CFingerprintList)
    lib.fpl_init.argtypes = []

    lib.fpl_destroy.restype = None
    lib.fpl_destroy.argtypes = [ctypes.POINTER(_CFingerprintList)]

    lib.fpl_add_path.restype = ctypes.c_int32
    lib.fpl_add_path.argtypes = [ctypes.POINTER(_CFingerprintList), ctypes.c_char_p,
                                 ctypes.c_char_p]

    lib.fpl_add_bytes.restype = ctypes.c_int32
    lib.fpl_add_bytes.argtypes = [ctypes.POINTER(_CFingerprintList), ctypes.c_char_p,
                                  ctypes.c_ulong, ctypes.c_char_p]

    lib.fpl_str.restype = ctypes.c_void_p
    lib.fpl_str.argtypes = [ctypes.POINTER(_CFingerprintList)]

    # Comparison functions
    lib.cl_fpl_all.restype = ctypes.POINTER(_CCompareList)
    lib.cl_fpl_all.argtypes = [ctypes.POINTER(_CFingerprintList), ctypes.c_uint8]

    lib.cl_fpl_vs_fpl.restype = ctypes.POINTER(_CCompareList)
    lib.cl_fpl_vs_fpl.argtypes = [ctypes.POINTER(_CFingerprintList),
                                  ctypes.POINTER(_CFingerprintList), ctypes.c_uint8]

    lib.cl_fp_vs_fpl.restype = ctypes.POINTER(_CCompareList)
    lib.cl_fp_vs_fpl.argtypes = [ctypes.POINTER(_CFingerprint), ctypes.POINTER(_CFingerprintList),
                                 ctypes.c_uint8]

    lib.cl_free.restype = None
    lib.cl_free.argtypes = [ctypes.POINTER(_CCompareList)]

    # String functions
    lib.str_free.restype = None
    lib.str_free.argtypes = [ctypes.c_void_p]

    lib.str_compare.restype = ctypes.c_int32
    lib.str_compare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]


# Set signatures
_setup_library_functions()


def _cl_to_list(cl_ptr) -> List[Comparison]:
    """Convert C comparison list to Python list."""
    if not cl_ptr:
        return []

    cl = cl_ptr.contents
    return [
        Comparison(
            cl.list[i].name1.decode() if cl.list[i].name1 else "",
            cl.list[i].name2.decode() if cl.list[i].name2 else "",
            cl.list[i].score
        )
        for i in range(cl.size)
    ]


class Fingerprint:
    """
    MRSHw Fingerprint class for individual file/data hashing.

    Similar to TLSH, this class represents a single fingerprint that can be
    used for similarity comparison with other fingerprints.

    Example:
        fp1 = Fingerprint("file1.txt")
        fp2 = Fingerprint()
        fp2.update(b"some binary data")

        similarity = fp1.compare(fp2)
        print(f"Similarity score: {similarity}")
    """

    def __init__(self, data: Optional[Union[str, bytes, Tuple[Union[str, bytes], str]]] = None):
        """
        Initialize a new fingerprint.

        Args:
            data: Optional initial data to hash. Can be:
                - str: file path
                - bytes: binary data
                - tuple: (data, label) where data is str/bytes and label is str
        """
        self._fp = lib.fp_init()
        if not self._fp:
            raise MRSHwError("Failed to initialize fingerprint")

        if data is not None:
            self.update(data)

    def __del__(self):
        """Cleanup C resources."""
        if hasattr(self, '_fp') and self._fp:
            lib.fp_destroy(self._fp)

    def update(self, data: Union[str, bytes, Tuple[Union[str, bytes], str]]) -> 'Fingerprint':
        """
        Update fingerprint with new data.

        Args:
            data: Data to add. Can be:
                - str: file path
                - bytes: binary data  
                - tuple: (data, label) where data is str/bytes and label is str

        Returns:
            Self for method chaining

        Raises:
            MRSHwError: If update operation fails
        """
        err = 0

        if isinstance(data, str):
            err = lib.fp_add_file(self._fp, data.encode(), None)
        elif isinstance(data, bytes):
            err = lib.fp_add_bytes(self._fp, data, len(data), b"n/a")
        elif isinstance(data, tuple):
            d, label = data
            label_bytes = label.encode() if isinstance(label, str) else label

            if isinstance(d, str):
                err = lib.fp_add_file(self._fp, d.encode(), label_bytes)
            elif isinstance(d, bytes):
                err = lib.fp_add_bytes(self._fp, d, len(d), label_bytes)
            else:
                raise TypeError(f"Unsupported data type in tuple: {type(d)}")
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

        if err != 0:
            raise MRSHwError(f"Failed to update fingerprint (error code: {err})")

        return self

    def hexdigest(self) -> str:
        """
        Get the hexadecimal digest of the fingerprint.

        Returns:
            Hexadecimal string representation of the fingerprint
        """
        raw = lib.fp_str(self._fp)
        if not raw:
            return ""

        try:
            data = ctypes.string_at(raw)
            return data.decode('utf-8', errors='replace')
        finally:
            lib.str_free(raw)

    def __str__(self) -> str:
        """String representation of the fingerprint."""
        return self.hexdigest()

    def __repr__(self) -> str:
        """Detailed string representation."""
        meta = self.metadata()
        return f"Fingerprint(name='{meta.name}', size={meta.size}, filters={meta.filters})"

    def metadata(self) -> Metadata:
        """
        Get metadata about the fingerprint.

        Returns:
            Metadata namedtuple containing name, size, and filter count
        """
        fp_contents = self._fp.contents
        name = fp_contents.file_name.rstrip(b'\0').decode('utf-8', errors='replace')
        return Metadata(name, fp_contents.filesize, fp_contents.amount_of_BF)

    def compare(self, other: 'Fingerprint') -> int:
        """
        Compare this fingerprint with another.

        Args:
            other: Another Fingerprint instance

        Returns:
            Similarity score (0-255, where 0 is identical)

        Raises:
            TypeError: If other is not a Fingerprint instance
        """
        if not isinstance(other, Fingerprint):
            raise TypeError("Can only compare with another Fingerprint instance")

        return lib.fp_compare(self._fp, other._fp)


class FingerprintList:
    """
    MRSHw Fingerprint List for managing multiple fingerprints.

    This class allows efficient batch operations on multiple fingerprints,
    similar to TLSH's batch processing capabilities.

    Example:
        fpl = FingerprintList()
        fpl.add("file1.txt")
        fpl.add("file2.txt")
        fpl += b"some data"

        # Compare all fingerprints against each other
        results = fpl.compare_all(threshold=50)
    """

    def __init__(self, data: Optional[Union[str, bytes, List,
                 Tuple[Union[str, bytes], str]]] = None):
        """
        Initialize a new fingerprint list.

        Args:
            data: Optional initial data to add
        """
        self._fpl = lib.fpl_init()
        if not self._fpl:
            raise MRSHwError("Failed to initialize fingerprint list")

        if data is not None:
            self.add(data)

    def __del__(self):
        """Cleanup C resources."""
        if hasattr(self, '_fpl') and self._fpl:
            lib.fpl_destroy(self._fpl)

    def add(self, data: Union[str, bytes, List,
            Tuple[Union[str, bytes], str]]) -> 'FingerprintList':
        """
        Add data to the fingerprint list.

        Args:
            data: Data to add. Can be:
                - str: file path
                - bytes: binary data
                - list: list of items to add
                - tuple: (data, label) pair

        Returns:
            Self for method chaining
        """
        if isinstance(data, str):
            lib.fpl_add_path(self._fpl, data.encode(), None)
        elif isinstance(data, bytes):
            lib.fpl_add_bytes(self._fpl, data, len(data), b"n/a")
        elif isinstance(data, tuple):
            d, label = data
            label_bytes = label.encode() if isinstance(label, str) else label

            if isinstance(d, str):
                lib.fpl_add_path(self._fpl, d.encode(), label_bytes)
            elif isinstance(d, bytes):
                lib.fpl_add_bytes(self._fpl, d, len(d), label_bytes)
            else:
                raise TypeError(f"Unsupported data type in tuple: {type(d)}")
        elif isinstance(data, (list, tuple)):
            for item in data:
                self.add(item)
        else:
            raise TypeError(f"Unsupported input type: {type(data)}")

        return self

    def __iadd__(self, other) -> 'FingerprintList':
        """Support += operator for adding data."""
        return self.add(other)

    def hexdigest(self) -> str:
        """Get string representation of all fingerprints."""
        raw = lib.fpl_str(self._fpl)
        if not raw:
            return ""

        try:
            data = ctypes.string_at(raw)
            return data.decode('utf-8', errors='replace')
        finally:
            lib.str_free(raw)

    def __str__(self) -> str:
        """String representation of fingerprint list."""
        return self.hexdigest()

    def compare_all(self, threshold: int = 0) -> List[Comparison]:
        """
        Compare all fingerprints in the list against each other.

        Args:
            threshold: Similarity threshold (0-255)

        Returns:
            List of Comparison namedtuples
        """
        cl_ptr = lib.cl_fpl_all(self._fpl, threshold)
        try:
            return _cl_to_list(cl_ptr)
        finally:
            if cl_ptr:
                lib.cl_free(cl_ptr)

    def compare_with(self, other: Union['Fingerprint', 'FingerprintList'],
                     threshold: int = 0) -> List[Comparison]:
        """
        Compare this fingerprint list with another fingerprint or list.

        Args:
            other: Fingerprint or FingerprintList to compare against
            threshold: Similarity threshold (0-255)

        Returns:
            List of Comparison namedtuples
        """
        cl_ptr = None

        try:
            if isinstance(other, Fingerprint):
                cl_ptr = lib.cl_fp_vs_fpl(other._fp, self._fpl, threshold)
            elif isinstance(other, FingerprintList):
                cl_ptr = lib.cl_fpl_vs_fpl(self._fpl, other._fpl, threshold)
            else:
                raise TypeError("Can only compare with Fingerprint or FingerprintList")

            return _cl_to_list(cl_ptr)
        finally:
            if cl_ptr:
                lib.cl_free(cl_ptr)


# Convenience functions
def hash(data: Union[str, bytes, Tuple[Union[str, bytes], str]]) -> str:
    """
    Generate MRSHw hash for data.

    Args:
        data: Data to hash (file path, bytes, or (data, label) tuple)

    Returns:
        Hexadecimal hash string
    """
    fp = Fingerprint(data)
    return fp.hexdigest()


def compare(entity1: Union[Fingerprint, FingerprintList, str],
           entity2: Union[Fingerprint, FingerprintList, str],
           threshold: int = 0) -> Union[int, List[Comparison]]:
    """
    Compare two entities.

    Args:
        entity1: First entity (Fingerprint, FingerprintList, or hash string)
        entity2: Second entity (Fingerprint, FingerprintList, or hash string)
        threshold: Similarity threshold for list comparisons

    Returns:
        For Fingerprint vs Fingerprint: similarity score (int)
        For other combinations: list of Comparison namedtuples
    """
    # Handle string hash comparisons
    if isinstance(entity1, str) and isinstance(entity2, str):
        return diff(entity1, entity2)

    # Handle Fingerprint comparisons
    if isinstance(entity1, Fingerprint) and isinstance(entity2, Fingerprint):
        return entity1.compare(entity2)

    # Handle mixed comparisons
    if isinstance(entity1, Fingerprint):
        if isinstance(entity2, FingerprintList):
            return entity2.compare_with(entity1, threshold)
    elif isinstance(entity1, FingerprintList):
        if not isinstance(entity2, str):
            return entity1.compare_with(entity2, threshold)

    raise TypeError("Unsupported comparison types")


def diff(hash1: str, hash2: str) -> int:
    """
    Calculate difference between two hash strings.

    Args:
        hash1: First hash string
        hash2: Second hash string

    Returns:
        Difference score
    """
    # Create byte objects and assign them to variables
    # This keeps them alive until the function returns
    hash1_bytes = hash1.encode()
    hash2_bytes = hash2.encode()

    return lib.str_compare(hash1_bytes, hash2_bytes)
