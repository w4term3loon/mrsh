"""
MRSHw (Malware Resistant Similarity Hashing wrapper) Python Library

A Python wrapper for the MRSHv2 C library providing similarity hashing
functionality for malware detection and file comparison.
"""

__version__ = "1.0.0"
__author__ = "w4term3loon"
__email__ = "ifkovics.barnabas@gmail.com"

from .core import (
    Fingerprint,
    FingerprintList,
    hash,
    compare,
    diff,
    MRSHwException,
    MRSHwError
)

__all__ = [
    'Fingerprint',
    'FingerprintList',
    'hash',
    'compare',
    'diff',
    'MRSHwException',
    'MRSHwError',
    '__version__'
]

