# MRSHw API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Classes](#core-classes)
   - [Fingerprint](#fingerprint)
   - [FingerprintList](#fingerprintlist)
5. [Utility Functions](#utility-functions)
6. [Data Types](#data-types)
7. [Error Handling](#error-handling)
8. [Command Line Interface](#command-line-interface)
9. [Advanced Usage](#advanced-usage)
10. [Performance Considerations](#performance-considerations)
11. [Examples](#examples)

---

## Overview

MRSHw (Malware Resistant Similarity Hashing) is a Python library that provides robust similarity hashing capabilities for malware detection and file comparison. It wraps a high-performance C library to deliver fast, accurate similarity measurements between files and binary data.

### Key Features

- **Fast similarity hashing** using bloom filters and advanced algorithms
- **Batch processing** capabilities for large datasets
- **Memory efficient** operations through C library integration
- **Flexible input types** supporting files, binary data, and labeled datasets
- **Command-line interface** for easy integration into workflows
- **Cross-platform compatibility** (Linux, with plans for Windows/macOS)

### Use Cases

- Malware family classification
- Duplicate file detection
- Binary similarity analysis
- Large-scale file clustering
- Incident response and threat hunting

---

## Installation

### Prerequisites

- Python 3.7 or higher
- Linux operating system (primary support)

### Install from PyPI

```bash
pip install mrshw
```

### Install from Source

```bash
git clone https://github.com/w4term3loon/mrsh
cd mrsh/bindings
pip install -e .
```

---

## Quick Start

```python
import mrsh

# Generate a hash for a file
file_hash = mrsh.hash("malware_sample.exe")
print(f"Hash: {file_hash}")

# Compare two files
fp1 = mrsh.Fingerprint("file1.exe")
fp2 = mrsh.Fingerprint("file2.exe")
similarity = fp1.compare(fp2)
print(f"Similarity score: {similarity}")

# Batch comparison
fpl = mrsh.FingerprintList()
fpl.add("sample1.exe")
fpl.add("sample2.exe") 
fpl.add("sample3.exe")
results = fpl.compare_all(threshold=50)
```

---

## Core Classes

### Fingerprint

The `Fingerprint` class represents a single MRSH hash and provides methods for creation, comparison, and metadata extraction.

#### Constructor

```python
Fingerprint(data=None)
```

**Parameters:**
- `data` (optional): Initial data to hash
  - `str`: File path
  - `bytes`: Binary data
  - `tuple`: `(data, label)` where `data` is `str`/`bytes` and `label` is `str`

**Raises:**
- `MRSHwError`: If fingerprint initialization fails

**Example:**
```python
# From file path
fp1 = mrsh.Fingerprint("/path/to/file.exe")

# From binary data
fp2 = mrsh.Fingerprint(b"\x4d\x5a\x90\x00...")

# With label
fp3 = mrsh.Fingerprint(("/path/to/file.exe", "sample_1"))

# Empty fingerprint
fp4 = mrsh.Fingerprint()
```

#### Methods

##### `update(data)`

Update the fingerprint with additional data.

**Parameters:**
- `data`: Data to add (same types as constructor)

**Returns:**
- `Fingerprint`: Self (for method chaining)

**Raises:**
- `MRSHwError`: If update operation fails
- `TypeError`: If data type is unsupported

**Example:**
```python
fp = mrsh.Fingerprint()
fp.update("file1.exe").update(b"additional_data")
```

##### `hexdigest()`

Get the hexadecimal representation of the fingerprint.

**Returns:**
- `str`: Hexadecimal digest string

**Example:**
```python
fp = mrsh.Fingerprint("sample.exe")
digest = fp.hexdigest()
print(f"Digest: {digest}")
```

##### `compare(other)`

Compare this fingerprint with another fingerprint.

**Parameters:**
- `other` (`Fingerprint`): Another fingerprint to compare against

**Returns:**
- `int`: Similarity score (0-255, where 0 indicates identical files)

**Raises:**
- `TypeError`: If `other` is not a Fingerprint instance

**Example:**
```python
fp1 = mrsh.Fingerprint("file1.exe")
fp2 = mrsh.Fingerprint("file2.exe")
score = fp1.compare(fp2)

if score < 50:
    print("Files are very similar")
elif score < 100:
    print("Files are moderately similar")
else:
    print("Files are different")
```

##### `metadata()`

Get metadata information about the fingerprint.

**Returns:**
- `Metadata`: Named tuple with fields:
  - `name` (`str`): File name or identifier
  - `size` (`int`): File size in bytes
  - `filters` (`int`): Number of bloom filters used

**Example:**
```python
fp = mrsh.Fingerprint("large_file.exe")
meta = fp.metadata()
print(f"File: {meta.name}, Size: {meta.size}, Filters: {meta.filters}")
```

#### Special Methods

- `__str__()`: Returns `hexdigest()`
- `__repr__()`: Returns detailed representation with metadata
- `__del__()`: Automatic cleanup of C resources

---

### FingerprintList

The `FingerprintList` class manages multiple fingerprints and provides efficient batch operations.

#### Constructor

```python
FingerprintList(data=None)
```

**Parameters:**
- `data` (optional): Initial data to add (supports same types as `add()`)

**Example:**
```python
# Empty list
fpl = mrsh.FingerprintList()

# With initial data
fpl = mrsh.FingerprintList(["file1.exe", "file2.exe"])
```

#### Methods

##### `add(data)`

Add data to the fingerprint list.

**Parameters:**
- `data`: Data to add
  - `str`: File path
  - `bytes`: Binary data
  - `list`: List of items to add recursively
  - `tuple`: `(data, label)` pair

**Returns:**
- `FingerprintList`: Self (for method chaining)

**Raises:**
- `TypeError`: If data type is unsupported

**Example:**
```python
fpl = mrsh.FingerprintList()
fpl.add("file1.exe")
fpl.add(b"binary_data")
fpl.add([("file2.exe", "sample_2"), ("file3.exe", "sample_3")])
```

##### `compare_all(threshold=0)`

Compare all fingerprints in the list against each other.

**Parameters:**
- `threshold` (`int`, optional): Similarity threshold (0-255). Only return comparisons with scores >= threshold. Default: 0

**Returns:**
- `List[Comparison]`: List of comparison results

**Example:**
```python
fpl = mrsh.FingerprintList()
fpl.add("malware1.exe")
fpl.add("malware2.exe")
fpl.add("benign.exe")

# Find all similar pairs (score < 50)
similar_pairs = fpl.compare_all(threshold=0)
for comp in similar_pairs:
    if comp.score < 50:
        print(f"{comp.hash1} is similar to {comp.hash2} (score: {comp.score})")
```

##### `compare_with(other, threshold=0)`

Compare this fingerprint list with another fingerprint or list.

**Parameters:**
- `other` (`Fingerprint` or `FingerprintList`): Entity to compare against
- `threshold` (`int`, optional): Similarity threshold (0-255). Default: 0

**Returns:**
- `List[Comparison]`: List of comparison results

**Raises:**
- `TypeError`: If `other` is not a supported type

**Example:**
```python
# Compare list against single fingerprint
fpl = mrsh.FingerprintList(["sample1.exe", "sample2.exe"])
target = mrsh.Fingerprint("unknown.exe")
matches = fpl.compare_with(target, threshold=0)

# Compare two lists
fpl1 = mrsh.FingerprintList(["known_malware1.exe", "known_malware2.exe"])
fpl2 = mrsh.FingerprintList(["unknown1.exe", "unknown2.exe"])
cross_matches = fpl1.compare_with(fpl2, threshold=60)
```

##### `hexdigest()`

Get string representation of all fingerprints in the list.

**Returns:**
- `str`: Combined string representation

#### Special Methods

- `__iadd__(other)`: Support for `+=` operator (equivalent to `add()`)
- `__str__()`: Returns `hexdigest()`
- `__del__()`: Automatic cleanup of C resources

**Example:**
```python
fpl = mrsh.FingerprintList()
fpl += "file1.exe"
fpl += ["file2.exe", "file3.exe"]
```

---

## Utility Functions

### `hash(data)`

Generate MRSH hash for data (convenience function).

**Parameters:**
- `data`: Data to hash (same types as `Fingerprint` constructor)

**Returns:**
- `str`: Hexadecimal hash string

**Example:**
```python
# Quick hash generation
hash1 = mrsh.hash("file.exe")
hash2 = mrsh.hash(b"binary_data")
hash3 = mrsh.hash(("labeled_file.exe", "sample_label"))
```

### `compare(entity1, entity2, threshold=0)`

Compare two entities (convenience function).

**Parameters:**
- `entity1`: First entity (`Fingerprint`, `FingerprintList`, or `str` hash)
- `entity2`: Second entity (`Fingerprint`, `FingerprintList`, or `str` hash)
- `threshold` (`int`, optional): Similarity threshold for list comparisons. Default: 0

**Returns:**
- `int`: Similarity score (for `Fingerprint` vs `Fingerprint`)
- `List[Comparison]`: Comparison results (for other combinations)

**Example:**
```python
# Compare hash strings
score = mrsh.compare("hash1...", "hash2...")

# Compare fingerprints
fp1 = mrsh.Fingerprint("file1.exe")
fp2 = mrsh.Fingerprint("file2.exe")
score = mrsh.compare(fp1, fp2)

# Compare fingerprint vs list
fpl = mrsh.FingerprintList(["file1.exe", "file2.exe"])
results = mrsh.compare(fp1, fpl, threshold=50)
```

### `diff(hash1, hash2)`

Calculate difference between two hash strings.

**Parameters:**
- `hash1` (`str`): First hash string
- `hash2` (`str`): Second hash string

**Returns:**
- `int`: Difference score

**Example:**
```python
hash1 = mrsh.hash("file1.exe")
hash2 = mrsh.hash("file2.exe")
difference = mrsh.diff(hash1, hash2)
```

### `scan_directory(directory, extensions=None, recursive=True)`

Scan a directory and create fingerprints for all files.

**Parameters:**
- `directory` (`str` or `Path`): Directory path to scan
- `extensions` (`List[str]`, optional): File extensions to include (e.g., `['.exe', '.dll']`)
- `recursive` (`bool`, optional): Whether to scan subdirectories. Default: `True`

**Returns:**
- `FingerprintList`: List containing all scanned files

**Raises:**
- `FileNotFoundError`: If directory doesn't exist

**Example:**
```python
# Scan for all executable files
fpl = mrsh.scan_directory("/malware/samples", 
                         extensions=['.exe', '.dll', '.sys'],
                         recursive=True)

# Compare all files in directory
results = fpl.compare_all(threshold=70)
print(f"Found {len(results)} similar file pairs")
```

### `batch_compare(files, threshold=50)`

Compare multiple files in batch.

**Parameters:**
- `files` (`List[str]` or `List[Path]`): List of file paths to compare
- `threshold` (`int`, optional): Similarity threshold. Default: 50

**Returns:**
- `List[Comparison]`: List of comparison results

**Example:**
```python
files = ["sample1.exe", "sample2.exe", "sample3.exe"]
similar_files = mrsh.batch_compare(files, threshold=60)

for comp in similar_files:
    print(f"Similar: {comp.hash1} <-> {comp.hash2} (score: {comp.score})")
```

---

## Data Types

### Named Tuples

#### `Metadata`

Contains fingerprint metadata information.

**Fields:**
- `name` (`str`): File name or identifier
- `size` (`int`): File size in bytes  
- `filters` (`int`): Number of bloom filters used

#### `Comparison`

Contains comparison result between two fingerprints.

**Fields:**
- `hash1` (`str`): First hash identifier
- `hash2` (`str`): Second hash identifier
- `score` (`int`): Similarity score (0-255, where 0 is most similar)

---

## Error Handling

### Exception Hierarchy

```
Exception
└── MRSHwException (base exception)
    ├── MRSHwError (operation failures)
    └── TypeError (type-related errors)
```

### `MRSHwException`

Base exception class for all MRSHw-related errors.

### `MRSHwError`

Raised when MRSHw operations fail (e.g., library loading, fingerprint creation).

**Common Causes:**
- Missing or corrupted `libmrsh.so`
- Invalid file permissions
- Corrupted input data
- Memory allocation failures

**Example:**
```python
try:
    fp = mrsh.Fingerprint("nonexistent_file.exe")
except mrsh.MRSHwError as e:
    print(f"MRSHw operation failed: {e}")
except FileNotFoundError as e:
    print(f"File not found: {e}")
```

---

## Command Line Interface

The MRSHw package includes a command-line interface for common operations.

### Installation Check

After installation, verify CLI availability:
```bash
mrsh --version
```

### Commands

#### `hash`

Generate hash for a single file.

```bash
mrsh hash <file_path>
```

**Options:**
- `file_path`: Path to file to hash

**Example:**
```bash
mrsh hash malware_sample.exe
# Output: a1b2c3d4e5f6...
```

#### `compare`

Compare two files or hash strings.

```bash
mrsh compare <input1> <input2> [--threshold THRESHOLD]
```

**Options:**
- `input1`: First file path or hash string
- `input2`: Second file path or hash string
- `--threshold`, `-t`: Similarity threshold (default: 0)

**Examples:**
```bash
# Compare two files
mrsh compare file1.exe file2.exe

# Compare hash strings
mrsh compare "a1b2c3..." "d4e5f6..."

# With threshold
mrsh compare file1.exe file2.exe --threshold 50
```

#### `scan`

Scan directory for similar files.

```bash
mrsh scan <directory> [options]
```

**Options:**
- `directory`: Directory path to scan
- `--recursive`, `-r`: Scan subdirectories (default: False)
- `--threshold`, `-t`: Similarity threshold (default: 50)
- `--extensions`, `-e`: File extensions to include

**Examples:**
```bash
# Basic directory scan
mrsh scan /malware/samples

# Recursive scan with file type filter
mrsh scan /malware/samples --recursive --extensions .exe .dll

# Custom similarity threshold
mrsh scan /malware/samples --threshold 30
```

---

## Advanced Usage

### Memory Management

MRSHw automatically manages C library resources, but you can force cleanup:

```python
fp = mrsh.Fingerprint("large_file.exe")
# ... use fingerprint
del fp  # Force immediate cleanup
```

### Performance Optimization

#### Batch Processing
Use `FingerprintList` for better performance with multiple files:

```python
# Efficient
fpl = mrsh.FingerprintList()
fpl.add(["file1.exe", "file2.exe", "file3.exe"])
results = fpl.compare_all()

# Less efficient
fps = [mrsh.Fingerprint(f) for f in ["file1.exe", "file2.exe", "file3.exe"]]
results = []
for i, fp1 in enumerate(fps):
    for fp2 in fps[i+1:]:
        results.append(mrsh.Comparison("fp1", "fp2", fp1.compare(fp2)))
```

#### Threshold Usage
Use appropriate thresholds to reduce result set size:

```python
# Get only very similar files (score < 30)
similar = fpl.compare_all(threshold=0)
very_similar = [c for c in similar if c.score < 30]

# More efficient: filter at C level
very_similar = fpl.compare_all(threshold=200)  # Inverse logic in some implementations
```

### Large Dataset Processing

For processing thousands of files:

```python
import os
from pathlib import Path

def process_large_dataset(root_dir, batch_size=1000):
    """Process large datasets in batches."""
    all_files = []

    # Collect all files
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(('.exe', '.dll', '.sys')):
                all_files.append(os.path.join(root, file))

    # Process in batches
    results = []
    for i in range(0, len(all_files), batch_size):
        batch = all_files[i:i+batch_size]
        fpl = mrsh.FingerprintList()

        for file_path in batch:
            try:
                fpl.add((file_path, Path(file_path).name))
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

        batch_results = fpl.compare_all(threshold=70)
        results.extend(batch_results)

        print(f"Processed batch {i//batch_size + 1}, found {len(batch_results)} matches")

    return results
```

### Integration with Other Libraries

#### Pandas Integration

```python
import pandas as pd
import mrsh

# Create DataFrame from comparison results
files = ["sample1.exe", "sample2.exe", "sample3.exe"]
fpl = mrsh.FingerprintList(files)
results = fpl.compare_all()

df = pd.DataFrame(results)
print(df.head())

# Analysis
similar_pairs = df[df['score'] < 50]
print(f"Found {len(similar_pairs)} similar pairs")
```

#### NetworkX for Clustering

```python
import networkx as nx
import mrsh

def create_similarity_graph(files, threshold=50):
    """Create similarity graph from files."""
    fpl = mrsh.FingerprintList(files)
    results = fpl.compare_all()

    G = nx.Graph()
    G.add_nodes_from(files)

    for comp in results:
        if comp.score < threshold:
            G.add_edge(comp.hash1, comp.hash2, weight=comp.score)

    return G

# Find clusters of similar files
files = ["file1.exe", "file2.exe", "file3.exe"]
G = create_similarity_graph(files, threshold=60)
clusters = list(nx.connected_components(G))
```

---

## Performance Considerations

### Benchmarks

Approximate performance on modern hardware:

- **Single file hashing**: ~1000 files/second
- **Pairwise comparison**: ~10,000 comparisons/second
- **Memory usage**: ~1KB per fingerprint

### Optimization Tips

1. **Use FingerprintList for batch operations**
   ```python
   # Good
   fpl = mrsh.FingerprintList(files)
   results = fpl.compare_all()

   # Avoid
   fps = [mrsh.Fingerprint(f) for f in files]
   # Manual pairwise comparisons...
   ```

2. **Set appropriate thresholds**
   ```python
   # Filter early to reduce memory usage
   results = fpl.compare_all(threshold=100)
   ```

3. **Process in batches for large datasets**
   ```python
   # Process 1000 files at a time instead of all at once
   for batch in chunks(all_files, 1000):
       fpl = mrsh.FingerprintList(batch)
       # Process batch...
   ```

4. **Use file extensions to filter**
   ```python
   # Only process relevant files
   fpl = mrsh.scan_directory("samples", extensions=['.exe', '.dll'])
   ```

### Memory Management

- Fingerprints are automatically cleaned up when Python objects are destroyed
- For long-running processes, manually delete large FingerprintList objects
- Monitor memory usage when processing thousands of files

---

## Examples

### Example 1: Basic Malware Family Detection

```python
import mrsh
from pathlib import Path

def detect_malware_families(sample_dir, similarity_threshold=60):
    """Detect potential malware families based on similarity."""

    # Scan directory for executable files
    fpl = mrsh.scan_directory(sample_dir, extensions=['.exe', '.dll'])
    print(f"Loaded {fpl._fpl.contents.size} samples")

    # Find similar pairs
    similar_pairs = fpl.compare_all(threshold=0)
    families = []

    # Group by similarity
    for comp in similar_pairs:
        if comp.score < similarity_threshold:
            families.append((comp.hash1, comp.hash2, comp.score))

    # Sort by similarity score
    families.sort(key=lambda x: x[2])

    print(f"\nFound {len(families)} potential family relationships:")
    for hash1, hash2, score in families[:10]:  # Show top 10
        print(f"  {hash1} <-> {hash2} (similarity: {score})")

    return families

# Usage
families = detect_malware_families("/malware/samples")
```

### Example 2: Unknown Sample Classification

```python
import mrsh

def classify_unknown_sample(unknown_file, known_samples_dir, threshold=50):
    """Classify an unknown sample against known malware families."""

    # Create fingerprint for unknown sample
    unknown_fp = mrsh.Fingerprint(unknown_file)
    print(f"Unknown sample hash: {unknown_fp.hexdigest()}")

    # Load known samples
    known_fpl = mrsh.scan_directory(known_samples_dir, extensions=['.exe'])

    # Compare unknown against known samples
    matches = known_fpl.compare_with(unknown_fp, threshold=0)

    # Find best matches
    close_matches = [(m.hash2, m.score) for m in matches if m.score < threshold]
    close_matches.sort(key=lambda x: x[1])  # Sort by score

    if close_matches:
        print(f"\nClosest matches for {unknown_file}:")
        for sample, score in close_matches[:5]:
            print(f"  {sample}: similarity score {score}")

        best_match = close_matches[0]
        if best_match[1] < 30:
            print(f"\nLikely family member: {best_match[0]} (very high similarity)")
        elif best_match[1] < 60:
            print(f"\nPossible family member: {best_match[0]} (moderate similarity)")
        else:
            print(f"\nPotentially related: {best_match[0]} (low similarity)")
    else:
        print("\nNo similar samples found in known database")

    return close_matches

# Usage
matches = classify_unknown_sample("unknown.exe", "/known_malware")
```

### Example 3: Duplicate File Detection

```python
import mrsh
import os

def find_duplicates(directory, exact_only=True):
    """Find duplicate files in a directory."""

    fpl = mrsh.scan_directory(directory, recursive=True)

    threshold = 0 if exact_only else 10  # 0 for exact duplicates
    comparisons = fpl.compare_all(threshold=threshold)

    duplicates = []
    for comp in comparisons:
        if comp.score <= threshold:
            duplicates.append((comp.hash1, comp.hash2, comp.score))

    # Group duplicates
    duplicate_groups = {}
    for hash1, hash2, score in duplicates:
        key = tuple(sorted([hash1, hash2]))
        if key not in duplicate_groups:
            duplicate_groups[key] = score

    print(f"Found {len(duplicate_groups)} duplicate pairs:")
    total_size_saved = 0

    for (file1, file2), score in duplicate_groups.items():
        try:
            size1 = os.path.getsize(file1) if os.path.exists(file1) else 0
            size2 = os.path.getsize(file2) if os.path.exists(file2) else 0
            size_saved = min(size1, size2)
            total_size_saved += size_saved

            print(f"  {file1} == {file2} (score: {score}, can save: {size_saved} bytes)")
        except OSError:
            print(f"  {file1} == {file2} (score: {score})")

    print(f"\nTotal space that could be saved: {total_size_saved:,} bytes")
    return list(duplicate_groups.keys())

# Usage
duplicates = find_duplicates("/downloads", exact_only=False)
```

### Example 4: Incremental Database Updates

```python
import mrsh
import pickle
import os
from datetime import datetime

class MalwareDatabase:
    """Incremental malware signature database."""

    def __init__(self, db_path="malware_db.pkl"):
        self.db_path = db_path
        self.signatures = {}  # hash -> metadata
        self.load_database()

    def load_database(self):
        """Load existing database."""
        if os.path.exists(self.db_path):
            with open(self.db_path, 'rb') as f:
                data = pickle.load(f)
                self.signatures = data.get('signatures', {})
            print(f"Loaded {len(self.signatures)} signatures from database")
        else:
            print("Created new database")

    def save_database(self):
        """Save database to disk."""
        data = {
            'signatures': self.signatures,
            'last_updated': datetime.now()
        }
        with open(self.db_path, 'wb') as f:
            pickle.dump(data, f)
        print(f"Saved {len(self.signatures)} signatures to database")

    def add_sample(self, file_path, family=None, tags=None):
        """Add new sample to database."""
        try:
            fp = mrsh.Fingerprint(file_path)
            hash_value = fp.hexdigest()
            meta = fp.metadata()

            self.signatures[hash_value] = {
                'file_path': file_path,
                'file_name': meta.name,
                'file_size': meta.size,
                'family': family,
                'tags': tags or [],
                'added_date': datetime.now()
            }

            print(f"Added {file_path} to database (hash: {hash_value[:16]}...)")
            return hash_value

        except Exception as e:
            print(f"Error adding {file_path}: {e}")
            return None

    def find_similar(self, file_path, threshold=50):
        """Find similar samples in database."""
        query_fp = mrsh.Fingerprint(file_path)
        query_hash = query_fp.hexdigest()

        # Create fingerprint list from database
        db_fpl = mrsh.FingerprintList()
        hash_to_path = {}

        for hash_val, metadata in self.signatures.items():
            # Use hash as identifier
            db_fpl.add((hash_val.encode(), hash_val))
            hash_to_path[hash_val] = metadata

        # Compare query against database
        matches = db_fpl.compare_with(query_fp, threshold=0)

        similar_samples = []
        for match in matches:
            if match.score < threshold:
                metadata = hash_to_path.get(match.hash2, {})
                similar_samples.append({
                    'hash': match.hash2,
                    'score': match.score,
                    'metadata': metadata
                })

        # Sort by similarity
        similar_samples.sort(key=lambda x: x['score'])
        return similar_samples

    def add_directory(self, directory, family=None):
        """Add all samples from directory."""
        files = []
        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                if filename.endswith(('.exe', '.dll', '.sys')):
                    files.append(os.path.join(root, filename))

        print(f"Adding {len(files)} samples from {directory}")

        for file_path in files:
            self.add_sample(file_path, family=family)

        self.save_database()

# Usage
db = MalwareDatabase()

# Add samples by family
db.add_directory("/malware/emotet", family="Emotet")
db.add_directory("/malware/wannacry", family="WannaCry")

# Query for similar samples
unknown_sample = "/unknown/suspicious.exe"
similar = db.find_similar(unknown_sample, threshold=60)

print(f"\nSimilar samples to {unknown_sample}:")
for match in similar[:5]:
    meta = match['metadata']
    print(f"  Family: {meta.get('family', 'Unknown')}")
    print(f"  File: {meta.get('file_name', 'N/A')}")
    print(f"  Score: {match['score']}")
    print(f"  Hash: {match['hash'][:16]}...")
    print()
```
