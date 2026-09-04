"""
MRSHw (Malware Resistant Similarity Hashing wrapper) Python Library

A Python wrapper for the MRSHv2 C library providing similarity hashing
functionality for malware detection and file comparison.
"""

__author__ = "w4term3loon"
__email__ = "ifkovics.barnabas@gmail.com"

from ._version import __version__

from .core import (
    Comparison,
    Fingerprint,
    FingerprintList,
    Metadata,
    hash,
    compare,
    diff,
    MRSHwDigestError,
    MRSHwException,
    MRSHwError
)

__all__ = [
    'Comparison',
    'Fingerprint',
    'FingerprintList',
    'Metadata',
    'hash',
    'compare',
    'diff',
    'MRSHwDigestError',
    'MRSHwException',
    'MRSHwError',
    '__version__'
]
