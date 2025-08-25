# mrshw

Thin, ctypes-based Python bindings for the [mrsh CLI tool](https://github.com/w4term3loon/mrsh). Implements the Bloom-filter–based similarity hashing algorithm originally proposed by Frank Breitinger and Harald Baier in their paper Similarity Preserving Hashing: Eligible Properties and a new Algorithm MRSH-v2 (da/sec Biometrics and Internet Security Research Group, Hochschule Darmstadt). Use Bloom-filter–based fingerprinting directly from Python with minimal overhead.

---

## Installation

Install from PyPI:

```bash
pip install mrshw
```

Or directly from GitHub (tagged release `v0.1.1`):

```bash
pip install git+https://github.com/w4term3loon/mrsh.git@v0.1.1
```

---

## Quickstart

```python
import mrsh

# Generate hash
hash_value = mrsh.hash("file.exe")

# Create and compare fingerprints
fp1 = mrsh.Fingerprint("file1.exe")
fp2 = mrsh.Fingerprint("file2.exe")
similarity = fp1.compare(fp2)

# Batch operations
fpl = mrsh.FingerprintList()
fpl.add("file1.exe")
fpl.add("file2.exe")
results = fpl.compare_all(threshold=50)
```

---

## License

* **Wrapper code:** MIT License. See the [LICENSE file](https://github.com/w4term3loon/mrsh/blob/master/bindings/LICENSE) for full terms.
* **Underlying C library:** Apache License 2.0. See its [repository license](https://github.com/w4term3loon/mrsh/blob/master/LICENSE.md).

