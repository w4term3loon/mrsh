# mrshw

Thin, ctypes-based Python bindings for the [mrsh CLI tool](https://github.com/w4term3loon/mrsh). Implements the Bloom-filter–based similarity hashing algorithm originally proposed by Frank Breitinger and Harald Baier in their paper Similarity Preserving Hashing: Eligible Properties and a new Algorithm MRSH-v2 (da/sec Biometrics and Internet Security Research Group, Hochschule Darmstadt). Use Bloom-filter–based fingerprinting directly from Python with minimal overhead.

---

## Installation

Install from [PyPI](pypi.org/project/mrshw):

```bash
pip install mrshw
```

Or directly from GitHub (tagged release `v1.0.0`):

```bash
pip install git+https://github.com/w4term3loon/mrsh.git@v1.0.0
```

---

## Quick start

```python
import mrsh

# Target
file = "file.bin"

# Generate hash
hash_path = mrsh.hash(file) # labeled: 'file.bin'
hash_binary = mrsh.hash(open(file, 'rb').read())

# Arbitrary binary data hash
hash_labeled_binary = mrsh.hash((b"cafebabe", data_name))

# Calculate similarity score
similarity_score = mrsh.diff(hash_path, hash_binary)
assert(similarity_score == 100)

# Create and compare hashes with metadata
fp1 = mrsh.Fingerprint("file1.bin")
fp2 = mrsh.Fingerprint("file2.bin")
similarity = fp1.compare(fp2)

# Batch operations
fpl = mrsh.FingerprintList()
fpl.add("file1.bin")
fpl.add("file2.bin")
results = fpl.compare_all(threshold=50)
```

---

## License

* **Wrapper code:** MIT License. See the [LICENSE file](https://github.com/w4term3loon/mrsh/blob/master/bindings/LICENSE) for full terms.
* **Underlying C library:** Apache License 2.0. See its [repository license](https://github.com/w4term3loon/mrsh/blob/master/LICENSE.md).

