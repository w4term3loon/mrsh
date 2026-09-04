# mrshw

`mrshw` is a small, ctypes-based Python interface to the MRSH-v2 similarity
hashing engine. The package has no runtime Python dependencies.

The distribution name and import name are `mrshw`. The console command is
`mrsh`.

## Installation

Version 1.1.0 is currently unreleased. Install the hardened development version
from this source tree:

```bash
python -m pip install .
```

Release wheels are platform-specific Linux wheels, not universal Python wheels.
Compiling from a source archive or checkout requires Python 3.10 or newer and a
C99 compiler.

OpenSSL is not required. Installation from a Git revision works because build
metadata is at the repository root, once that revision has been pushed:

```bash
python -m pip install "git+https://github.com/w4term3loon/mrsh.git@REVISION"
```

The published 1.0.0 package has known native memory-safety and parser defects.
Do not use it with untrusted inputs; verify that `mrshw.__version__` is at least
1.1.0.

## Quick start

```python
import mrshw

digest_from_path = mrshw.hash("file.bin")
digest_from_bytes = mrshw.hash((b"cafebabe", "memory-sample"))

with mrshw.Fingerprint("file.bin") as first:
    with mrshw.Fingerprint.from_digest(digest_from_path) as second:
        score = first.compare(second)
        assert score == 100

with mrshw.FingerprintList() as fingerprints:
    fingerprints.add("file1.bin")
    fingerprints.add((b"binary data", "memory-sample"))
    matches = fingerprints.compare_all(threshold=50)
```

Scores range from 0 to 100, where 100 means identical fingerprints. A threshold
retains scores greater than or equal to it and must be an integer in that same
range. Scores are similarity indicators, not cryptographic identity proofs.

## Input and ownership rules

- A `str` data argument is a filesystem path. Pass `(data, label)` to supply an
  explicit label. Explicit paths are limited to 65,535 encoded bytes and are
  validated before they are copied or split into components.
- Explicit labels are encoded as UTF-8 and may contain at most 65,535 bytes.
  Path-derived labels preserve undecodable POSIX filename bytes. Colons are
  supported; ASCII control characters and DEL are rejected so untrusted labels
  cannot inject terminal control sequences into digest or comparison output.
- Empty files and `b""` are valid and produce a deterministic empty fingerprint.
- Hashing streams to EOF in constant memory and performs work linear in the
  number of bytes. It deliberately has no arbitrary file-size cutoff; apply
  storage quotas or process timeouts when an adversary controls file size or
  growth.
- Fingerprints are capped at 65,535 Bloom filters (about 32 MiB when serialized);
  larger inputs fail cleanly instead of wrapping the count.
- Fingerprint lists are capped at 100,000 entries and 256 MiB when serialized.
  Parsing a list outside either limit raises `MRSHwDigestError`; adding more
  than 100,000 entries or serializing more than 256 MiB raises `MRSHwError`.
- Nested list/tuple input is limited to 256 container levels and 200,001
  scheduled nodes. Cycles and larger shared-container graphs are rejected
  without changing the destination list.
- A comparison returns at most 1,000,000 records and copies at most 256 MiB of
  labels into its result. Comparison candidates and aggregate Bloom-filter work
  are each capped at 1,000,000 per call. Exceeding a ceiling raises
  `MRSHwError` before partial results are returned.
- Parsed digests are strictly validated. `MRSHwDigestError` is raised for
  malformed fields, invalid numbers, impossible filter counts, or invalid hex.
- `Fingerprint` and `FingerprintList` own native memory. Use a `with` statement
  or call the idempotent `close()` method. Operations after close raise
  `MRSHwError`.
- `copy.copy`, `copy.deepcopy`, and pickle round trips create independent native
  objects; they never share an owning pointer.

## Directory scanning

```python
from mrshw.utils import scan_directory

with scan_directory("samples", extensions=["exe", ".dll"], recursive=True) as items:
    matches = items.compare_all(60)
```

With `extensions=None` (the default), all regular files are included; an empty
extension iterable matches no files. Extensions are case-insensitive and may be
written with or without a leading dot. Extension filters are limited to 4,096
items and 1 MiB of encoded text. Paths are processed in deterministic order,
and scanning never changes the process-wide working directory. Scans pin the
filesystem root or current directory, then open every supplied root and scanned
component relative to verified directory descriptors without following
symlinks. Concurrent replacement is rejected. Traversal is limited to 100,000
visited entries, 256 MiB of recorded relative path data, and 256 directory
levels.

`batch_compare()` likewise consumes at most 100,000 explicit file paths. It
opens and identity-checks every component without following symlinks, and
rejects concurrent replacement instead of hashing a redirected file.

## Command line

```bash
mrsh hash FILE
mrsh compare FILE1 FILE2
mrsh compare DIGEST1 DIGEST2
mrsh scan DIRECTORY --recursive --threshold 50 --extensions exe dll
mrsh --version
```

`mrsh compare` always prints the score and exits 0 when it meets the requested
threshold or 1 when it does not. Invalid command-line input exits 2.

See the [API reference](https://github.com/w4term3loon/mrsh/blob/master/bindings/docs/api.md)
for the complete supported surface.

## Licenses

The wrapper is MIT-licensed; see
[bindings/LICENSE](https://github.com/w4term3loon/mrsh/blob/master/bindings/LICENSE).
The bundled MRSH-v2 engine is Apache-2.0-licensed; see the repository’s
[LICENSE.md](https://github.com/w4term3loon/mrsh/blob/master/LICENSE.md) and
[NOTICE.txt](https://github.com/w4term3loon/mrsh/blob/master/NOTICE.txt).
