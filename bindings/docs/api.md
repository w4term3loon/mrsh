# mrshw API reference

Install the `mrshw` distribution and import it with `import mrshw`. The separate
name `mrsh` refers only to the installed console command.

## Scores and digests

All comparisons return an integer similarity score in the inclusive range
0–100. A score of 100 means the fingerprints are identical; larger numbers mean
more similarity. Comparison thresholds are inclusive integers from 0 through
100. `bool`, floats, strings, negative values, and values over 100 are rejected.

A serialized fingerprint has five conceptual fields (parsed from the right so a
label may itself contain colons):

```text
label:size:filter_count:blocks_in_last_filter:hex_filters
```

Explicit labels are UTF-8 strings of at most 65,535 encoded bytes; path-derived
labels preserve undecodable POSIX filename bytes with the platform filesystem
encoding. Colons are supported; carriage returns, newlines, and NUL are
rejected, as are all other ASCII control characters and DEL. This prevents
untrusted labels from injecting terminal controls into digest or comparison
output. Parsers work from the fixed numeric/hex fields at the right, then
validate every field, the number and length of filters, numeric ranges, and
every hex digit before allocating native objects.

Fingerprints are bounded to 65,535 Bloom filters (about 32 MiB of serialized
hex). Inputs that would require more filters fail with `MRSHwError` instead of
overflowing metadata or allocating an unbounded digest.

File hashing streams to EOF with constant memory overhead and does not impose
an arbitrary byte-size limit. Runtime is linear in bytes read. Callers handling
adversary-controlled storage should enforce file-size, aggregate-I/O, and
process-time budgets appropriate to their environment.

Serialized fingerprint lists are limited to 100,000 entries and 256 MiB.
Cross-list and all-pairs operations return at most 1,000,000 comparison records
and copy at most 256 MiB of labels into a result. Candidate pairs and aggregate
Bloom-filter comparison work are also each limited to 1,000,000 per call and
are preflighted before results are built. A digest outside its limits raises
`MRSHwDigestError`; exceeding an entry-count, serialization, comparison, or
result limit raises `MRSHwError`.

## Exceptions

`MRSHwException`
: Base exception for the package.

`MRSHwError`
: Native operation, I/O, allocation, ownership, or library-loading failure.

`MRSHwDigestError`
: A serialized fingerprint is malformed or outside the supported limits.

## Value types

`Metadata(name, size, filters)`
: Fingerprint label, unsigned 64-bit byte length, and actual serialized
  Bloom-filter count.

`Comparison(hash1, hash2, score)`
: The two labels and their 0–100 similarity score.

## `Fingerprint`

```python
Fingerprint(data=None)
```

`data` may be a filesystem path (`str`), raw data (`bytes`), or a `(data, label)`
tuple. Omitting it creates a valid empty object. Supplying new data with
`update()` atomically replaces the current fingerprint; a failed update leaves
the previous value usable. Explicit paths are limited to 65,535 encoded bytes
and are bounded before encoding or component splitting.

`Fingerprint.from_digest(digest)`
: Parse one strict serialized fingerprint.

`update(data) -> Fingerprint`
: Replace the fingerprint and return `self`.

`hexdigest() -> str`
: Return the serialized fingerprint.

`metadata() -> Metadata`
: Return its initialized label, size, and filter count.

`compare(other) -> int`
: Compare with another open `Fingerprint`.

`close() -> None`
: Release native memory. Calling it more than once is safe.

`closed -> bool`
: Whether native memory has been released.

The class is a context manager. Shallow copies, deep copies, and objects restored
from pickle own independent native allocations. Native-backed operations on a
closed object raise `MRSHwError`.

## `FingerprintList`

```python
FingerprintList(data=None)
```

`data` accepts the same individual values as `Fingerprint`, or a list of those
values.

`FingerprintList.from_digest(digest)`
: Parse newline-separated fingerprints as one list. If any line is invalid, no
  partially parsed list is returned.

`add(data, *, recursive=False) -> FingerprintList`
: Add one value or a list of values and return `self`. `+=` is equivalent.
  Files and explicit top-level file symlinks are accepted. A directory adds its
  immediate regular files; set `recursive=True` to descend into subdirectories.
  Directory-entry symlinks are skipped. Nested containers are capped at 256
  levels and 200,001 scheduled nodes; cycles and larger shared graphs are
  rejected. Multi-item updates are atomic.

`hexdigest() -> str`
: Serialize the list as one fingerprint per line.

`compare_all(threshold=0) -> list[Comparison]`
: Compare every unique pair within the list.

`compare_with(other, threshold=0) -> list[Comparison]`
: Compare the list with a `Fingerprint` or another `FingerprintList`.

`close()`, `closed`
: Follow the same ownership rules as `Fingerprint`.

## Convenience functions

`hash(data) -> str`
: Create and serialize a fingerprint for a path, bytes, or `(data, label)` tuple.

`diff(digest1, digest2) -> int`
: Strictly parse and compare two serialized fingerprints. Invalid input raises
  `MRSHwDigestError`; it is never converted to an ordinary zero score.

`compare(first, second, threshold=0)`
: Dispatch between two fingerprints, lists, or two serialized digest strings.
  The threshold is validated for every call and filters list-returning
  comparisons. Scalar fingerprint or digest comparisons return their raw
  0–100 score regardless of the validated threshold.

## Utilities

```python
scan_directory(directory, extensions=None, recursive=True) -> FingerprintList
```

Scan regular files in deterministic path order without changing the process
working directory. An omitted extension filter includes all files. Extension
matching is case-insensitive and accepts values such as `"exe"` or `".exe"`;
an empty iterable matches no files. A filter is capped at 4,096 items and 1 MiB
of encoded text. The filesystem root or current-directory descriptor remains
pinned, every supplied root and scanned path component is opened
descriptor-relatively with no-follow semantics, and recorded device/inode
identities are rechecked before hashing an already-opened file. Symlink swaps
and concurrent identity changes fail with `MRSHwError`. The traversal counts
all entry types and is capped at 100,000 entries, 256 MiB of relative path data,
and 256 directory levels.

```python
batch_compare(files, threshold=50) -> list[Comparison]
```

Hash and compare up to 100,000 filesystem paths. Inputs are consumed
incrementally rather than accumulated in an unbounded Python list. Every path
component and final regular file is opened descriptor-relatively with
no-follow semantics and a device/inode identity check; symlinks and concurrent
replacement fail with `MRSHwError`.

## Console command

```text
mrsh hash FILE
mrsh compare INPUT1 INPUT2 [-t THRESHOLD]
mrsh scan DIRECTORY [-r] [-t THRESHOLD] [-e EXTENSION ...]
mrsh --version
```

For `compare`, two existing regular files are hashed; otherwise both arguments
are treated as serialized fingerprints. Reported values are similarity scores.
The command exits 0 when the score meets `--threshold`, 1 when it is below the
threshold, and 2 for invalid command-line input.
