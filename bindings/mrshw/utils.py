"""
Utility functions for MRSHw operations.
"""

from pathlib import Path
from typing import List, Union
from .core import FingerprintList


def scan_directory(directory: Union[str, Path],
                  extensions: List[str] = [],
                  recursive: bool = True) -> FingerprintList:
    """
    Scan a directory and create fingerprints for all files.

    Args:
        directory: Directory path to scan
        extensions: List of file extensions to include (e.g., ['.exe', '.dll'])
        recursive: Whether to scan subdirectories

    Returns:
        FingerprintList containing all scanned files
    """
    directory = Path(directory)
    fpl = FingerprintList()

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    pattern = "**/*" if recursive else "*"

    for file_path in directory.glob(pattern):
        if file_path.is_file():
            if extensions is None or file_path.suffix.lower() in extensions:
                try:
                    fpl.add((str(file_path), file_path.name))
                except Exception as e:
                    print(f"Warning: Could not process {file_path}: {e}")

    return fpl


def batch_compare(files: List[Union[str, Path]], threshold: int = 50) -> List:
    """
    Compare multiple files in batch.

    Args:
        files: List of file paths to compare
        threshold: Similarity threshold

    Returns:
        List of comparison results
    """
    fpl = FingerprintList()

    for file_path in files:
        if Path(file_path).exists():
            fpl.add((str(file_path), Path(file_path).name))

    return fpl.compare_all(threshold)
