# MRSH algorithm

> [!IMPORTANT]
> This algorithm was originally proposed by Frank Breitinger and Harald Baier in their paper: [Similarity Preserving Hashing: Eligible  Properties and a new Algorithm MRSH-v2](https://link.springer.com/chapter/10.1007/978-3-642-39891-9_11) as part of their research at the **da/sec - Biometrics and Internet Security Research Group Hochschule Darmstadt, Darmstadt, Germany**.

> [!NOTE]
> Modification, development and publication are done under the original [LICENSE](./LICENSE.md). Please preserve original license headers and attribution when modifying or redistributing this code.

### Abstract
Hash functions are a widespread class of functions in computer science and used in several applications, e.g. in computer forensics to identify known files. One basic property of cryptographic hash functions is the avalanche effect that causes a significantly different output if an input is changed slightly. As some applications also need to identify similar files (e.g. spam/virus detection) this raised the need for similarity preserving hashing. In recent years, several approaches came up, all with different namings, properties, strengths and weaknesses which is due to a missing definition. Based on the properties and use cases of traditional hash functions this paper discusses a uniform naming and properties which is a first step towards a suitable definition of similarity preserving hashing. Additionally, we extend the algorithm MRSH for similarity preserving hashing to its successor MRSH-v2, which has three specialties. First, it fulfills all our proposed defining properties, second, it outperforms existing approaches especially with respect to run time performance and third it has two detections modes. The regular mode of MRSH-v2 is used to identify similar files whereas the f-mode is optimal for fragment detection, i.e. to identify similar parts of a file.

## Python Bindings

This repository includes `ctypes`-based Python bindings for the `mrsh` CLI tool.

- PyPI: [mrshw](https://pypi.org/project/mrshw/)
- Source: [`bindings/`](./bindings/)
- Install: `pip install mrshw`

For usage, see the [binding README](./bindings/README.md).

