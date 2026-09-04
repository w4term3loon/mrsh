# MRSH-v2

This repository contains the original MRSH-v2 similarity-hashing engine, a small
C ABI, and the `mrshw` Python package.

MRSH-v2 was proposed by Frank Breitinger and Harald Baier for similarity and
fragment detection. A similarity score is an integer from **0 through 100**:
100 means identical fingerprints and higher values mean greater similarity.
MRSH is not a cryptographic hash and its score is not proof that two inputs are
the same or safe.

## Python package

The distribution name and Python import are both `mrshw`; the installed command
is named `mrsh`.

Version 1.1.0 is currently unreleased. The published 1.0.0 package contains
known native memory-safety and parser defects and must not process untrusted
input. Install the hardened development version from this source tree:

```bash
python -m pip install .
```

Release wheels are platform-specific and contain a native library compiled for
their advertised Linux platform. When no compatible wheel is available, pip
builds that library from the C sources in the source archive. A C99 compiler,
Python development headers, and the standard C and math libraries are required;
OpenSSL is not required.

Installing a checkout, commit, or tag works from the repository root once that
revision is available:

```bash
python -m pip install "git+https://github.com/w4term3loon/mrsh.git@REVISION"
```

After installation, verify that `mrshw.__version__` is at least 1.1.0.

```python
import mrshw

digest = mrshw.hash((b"binary data", "sample"))

with mrshw.Fingerprint((b"binary data", "first")) as first:
    with mrshw.Fingerprint.from_digest(digest) as second:
        assert first.compare(second) == 100
```

See [the Python guide](bindings/README.md) and
[API reference](bindings/docs/api.md) for batch comparison, directory scanning,
digest validation, ownership, and CLI usage.

## Native command-line tool

The standalone research CLI can be built on a POSIX system with:

```bash
make
./mrsh -h
```

Common operations are:

```bash
./mrsh -p FILE                     # print a digest
./mrsh -c FILE1 FILE2              # compare paths
./mrsh -g -t 50 DIRECTORY          # compare all inputs, score >= 50
./mrsh -L DIGEST_LIST              # compare a saved list with itself
./mrsh -L FIRST_LIST SECOND_LIST   # compare two saved lists
```

Use `-r` to recurse into directories and `-f` for whole-file comparison mode.
Malformed list records and invalid thresholds are errors. One operation may
consider at most 1,000,000 candidate fingerprint pairs and 1,000,000 aggregate
Bloom-filter pairs. Comparison output is preflighted and capped at 256 MiB;
larger untrusted workloads fail before anything is written. Hashing itself
intentionally streams files to EOF and takes time linear in the number of bytes.
Apply file-size quotas or process timeouts when storage size or growth is
controlled by an adversary.

## Development

```bash
python -m pip install -e ".[test]"
python -m pytest
make
```

CI runs the regression suite on supported Python versions, repeats it with
AddressSanitizer and UndefinedBehaviorSanitizer, and validates wheel/source
archive contents. Release workflows build separate manylinux wheels for
x86-64 and AArch64; they do not publish automatically.

## Attribution and licenses

The MRSH-v2 engine is licensed under Apache License 2.0; see [LICENSE.md](LICENSE.md)
and [NOTICE.txt](NOTICE.txt). The Python wrapper is MIT-licensed; see
[bindings/LICENSE](bindings/LICENSE). Academic users are asked to cite:

> Frank Breitinger and Harald Baier. “Similarity Preserving Hashing: Eligible
> Properties and a New Algorithm MRSH-v2.” Digital Forensics and Cyber Crime,
> 2013, pp. 167–182.
