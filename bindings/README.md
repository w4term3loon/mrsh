# mrshw

Thin, ctypes-based Python bindings for the [mrsh CLI tool](https://github.com/w4term3loon/mrsh). Implements the Bloom-filter–based similarity hashing algorithm originally proposed by Frank Breitinger and Harald Baier in their paper Similarity Preserving Hashing: Eligible Properties and a new Algorithm MRSH-v2 (da/sec Biometrics and Internet Security Research Group, Hochschule Darmstadt). Use Bloom-filter–based fingerprinting directly from Python with minimal overhead.

---

## Installation

Install from PyPI:

```bash
pip install mrshw
```

Or directly from GitHub (tagged release `v0.1.0b3`):

```bash
pip install git+https://github.com/w4term3loon/mrsh.git@v0.1.0b3
```

---

## Quickstart

```python
import mrshw as mrsh

# 1. Single-fingerprint API
fp = mrsh.fp("path/to/file.bin")
print(str(fp))            # raw metadata + hex-encoded Bloom filters
print(fp.meta())          # Metadata(name, filesize, filter_count)

# 2. Quick hash helper
print(mrsh.hash("path/to/file.bin"))

# 3. Fingerprint-list API
fpl = mrsh.fpl()
fpl += "a.bin"
fpl += ("b.bin", "label_b")
fpl += open('c.bin', 'rb').read()
print(str(fpl))           # one line per fingerprint

# 4. Compare two fingerprints
cmp = mrsh.compare(fp, mrsh.fp("other.bin"))
print(cmp.hash1, cmp.hash2, cmp.score)

# 5. Compare all in a list
results = fpl.compare_all(threshold=10)
for comp in results:
    print(comp.hash1, comp.hash2, comp.score)
```

---

## License

* **Wrapper code:** MIT License. See the [LICENSE file](https://github.com/w4term3loon/mrsh/blob/tree/master/bindings/LICENSE) for full terms.
* **Underlying C library:** Apache License 2.0. See its [repository license](https://https://github.com/w4term3loon/mrsh/blob/master/LICENSE.md).

