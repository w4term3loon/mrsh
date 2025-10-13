# MRSHw API Reference

This document provides a minimal API reference for the `mrshw` Python library and its command-line interface.

## Python Library (`mrshw`)

The core of the tool is the Python library, which can be used by importing `mrshw`.

### Core Classes

#### `mrshw.Fingerprint`

Represents a single MRSH similarity hash for a file or binary data.

- `mrshw.Fingerprint(data=None)` — Initializes a fingerprint. The optional `data` argument can be a file path (`str`), raw binary data (`bytes`), or a tuple of `(data, label)`.
- `.update(data)` — Adds more data to an existing fingerprint.
- `.hexdigest() -> str` — Returns the complete fingerprint as a hexadecimal string.
- `.compare(other_fingerprint) -> int` — Compares the fingerprint to another `Fingerprint` instance. Returns a similarity score from 0-100, where a lower score indicates higher similarity.
- `.metadata() -> Metadata` — Returns a named tuple containing the fingerprint's metadata: `.name`, `.size`, and `.filters`.

#### `mrshw.FingerprintList`

Manages a collection of `Fingerprint` objects for efficient batch operations.

- `mrshw.FingerprintList(data=None)` — Initializes a list of fingerprints. `data` can be a single item or a list of items to add.
- `.add(data)` — Adds one or more items to the list. Supports file paths, binary data, or lists of these types.
- `.compare_all(threshold=0) -> List[Comparison]` — Compares every fingerprint in the list against every other one. Returns a list of `Comparison` objects for any matches that meet the similarity `threshold`.
- `.compare_with(other, threshold=0) -> List[Comparison]` — Compares all fingerprints in the list against an external `Fingerprint` or another `FingerprintList`.

### Utility Functions

- `mrshw.hash(data) -> str` — A simple function to quickly generate an MRSH hash for a file or bytes.
- `mrshw.diff(hash1, hash2) -> int` — Calculates the similarity score between two MRSH hash strings.

## Command-Line Interface (CLI)

The `mrsh` command provides direct access to the tool's core functionality from the terminal.

### `mrsh hash`

Generates a hash for a single file.

```bash
mrsh hash <file_path>
```

### `mrsh compare`

Compares two files or two existing hash strings and returns the similarity score.

```bash
# Compare two files
mrsh compare <file1_path> <file2_path>

# Compare two hash strings
mrsh compare <hash_string1> <hash_string2>
```

### `mrsh scan`

Scans a directory to find and report similar files within it.

```bash
mrsh scan <directory_path> [options]
```

**Options:**

- `-r`, `--recursive` — Scan subdirectories.
- `-t`, `--threshold` — Set a similarity score threshold for reporting (default: 50).
- `-e`, `--extensions` — Filter by specific file extensions (e.g., `.exe .dll`).
