# MRSH Python API Documentation

**Multi-Resolution Similarity Hashing (MRSH)** - A fast and efficient similarity hashing library for detecting similar files and content.

## Quick Start

```python
import mrshw as mrsh

# Create fingerprints
fp1 = mrsh.fp("document.txt")
fp2 = mrsh.fp(b"Binary content")

# Compare similarity
result = mrsh.compare(fp1, fp2)
print(f"Similarity: {result[0].score}%")

# Work with multiple files
fpl = mrsh.fpl(["file1.txt", "file2.txt", "file3.txt"])
matches = fpl.compare_all(threshold=75)
```

## Core Functions

### `mrsh.fp(data=None) -> _MRSH_fp`
Create a single fingerprint object.

**Parameters:**
- `data` (optional): Input data to fingerprint
  - `str`: File path
  - `bytes`: Raw binary data  
  - `tuple`: `(data, label)` where data is str/bytes and label is custom name

**Returns:** Fingerprint object

**Examples:**
```python
fp1 = mrsh.fp("document.pdf")           # From file
fp2 = mrsh.fp(b"Hello World")           # From bytes
fp3 = mrsh.fp(("data.bin", "MyFile"))   # With custom label
```

### `mrsh.fpl(data=None) -> _MRSH_fpl`
Create a fingerprint list for multiple items.

**Parameters:**
- `data` (optional): Initial data to add
  - `str`: File/directory path
  - `list`: List of files/data to process
  - Other types supported by `.add()`

**Returns:** Fingerprint list object

**Examples:**
```python
fpl1 = mrsh.fpl()                       # Empty list
fpl2 = mrsh.fpl("directory/")           # From directory
fpl3 = mrsh.fpl(["f1.txt", "f2.txt"])   # From file list
```

### `mrsh.hash(data) -> str`
Convenience function to get hash string directly.

**Parameters:**
- `data`: Same as `mrsh.fp()`

**Returns:** Hex-encoded hash string

**Example:**
```python
hash_str = mrsh.hash("document.txt")
print(hash_str)  # "filename:size:filters:blocks:HEXDATA..."
```

### `mrsh.compare(entity1, entity2, threshold=0) -> list[Comparison]`
Compare two entities (fingerprints or lists).

**Parameters:**
- `entity1`: First entity (`_MRSH_fp` or `_MRSH_fpl`)
- `entity2`: Second entity (`_MRSH_fp` or `_MRSH_fpl`)  
- `threshold`: Minimum similarity score (0-100)

**Returns:** List of `Comparison` namedtuples with fields:
- `hash1`: First item identifier
- `hash2`: Second item identifier  
- `score`: Similarity score (0-100)

**Supported combinations:**
- Fingerprint vs Fingerprint
- Fingerprint vs List
- List vs Fingerprint  
- List vs List

**Examples:**
```python
# Single vs single
result = mrsh.compare(fp1, fp2, threshold=50)

# Single vs list
result = mrsh.compare(fp1, fpl1, threshold=75)

# List vs list (cross-comparison)
result = mrsh.compare(fpl1, fpl2, threshold=60)
```

## Fingerprint Object (`_MRSH_fp`)

### Methods

#### `.add(data) -> self`
Add data to existing fingerprint.

**Parameters:**
- `data`: Same formats as `mrsh.fp()`

**Returns:** Self for chaining

#### `.meta() -> Metadata`
Get fingerprint metadata.

**Returns:** `Metadata` namedtuple with:
- `name`: File/label name
- `size`: Data size in bytes
- `filters`: Number of bloom filters

#### `.__str__() -> str`
Get hex-encoded fingerprint string.

### Example
```python
fp = mrsh.fp()
fp.add("file1.txt").add(b"extra data")

meta = fp.meta()
print(f"Name: {meta.name}, Size: {meta.size}")
print(f"Hash: {fp}")
```

## Fingerprint List Object (`_MRSH_fpl`)

### Methods

#### `.add(data) -> self`
Add item(s) to the list.

**Parameters:**
- `data`: 
  - `str`: File/directory path
  - `bytes`: Binary data
  - `tuple`: `(data, label)`
  - `list`: Multiple items to add

**Returns:** Self for chaining

#### `.__iadd__(other) -> self`
Add items using `+=` operator.

#### `.compare_all(threshold=0) -> list[Comparison]`
Compare all items within the list against each other.

**Parameters:**
- `threshold`: Minimum similarity score

**Returns:** List of comparisons above threshold

### Examples
```python
fpl = mrsh.fpl()
fpl.add("file1.txt")
fpl.add(b"Binary data")
fpl += "file2.txt"  # Using += operator

# Find duplicates
duplicates = fpl.compare_all(threshold=90)
for dup in duplicates:
    print(f"Potential duplicate: {dup.hash1} vs {dup.hash2}")
```

## Data Types

### `Comparison` namedtuple
Result of comparison operations.
- `hash1` (str): First item identifier
- `hash2` (str): Second item identifier  
- `score` (int): Similarity score 0-100

### `Metadata` namedtuple  
Fingerprint metadata information.
- `name` (str): Item name/label
- `size` (int): Data size in bytes
- `filters` (int): Number of bloom filters

## Usage Patterns

### Duplicate Detection
```python
# Find duplicate files in directory
files = mrsh.fpl("./documents/")
duplicates = files.compare_all(threshold=95)

for dup in duplicates:
    print(f"Duplicate found: {dup.hash1} ≈ {dup.hash2} ({dup.score}%)")
```

### Content Similarity Search
```python
# Search for similar content
corpus = mrsh.fpl()
corpus.add("doc1.txt")
corpus.add("doc2.txt") 
corpus.add("doc3.txt")

query = mrsh.fp("query.txt")
similar = mrsh.compare(query, corpus, threshold=70)

for match in similar:
    print(f"Similar document: {match.hash2} ({match.score}% match)")
```

### Batch Processing
```python
# Process multiple files efficiently  
processor = mrsh.fpl()

files = ["file1.txt", "file2.txt", "file3.txt"]
for filename in files:
    try:
        processor.add((filename, f"processed_{filename}"))
    except Exception as e:
        print(f"Failed to process {filename}: {e}")

# Find all similarities
results = processor.compare_all(threshold=50)
```

### Cross-Collection Comparison
```python
# Compare two different collections
collection_a = mrsh.fpl(["set_a_1.txt", "set_a_2.txt"])
collection_b = mrsh.fpl(["set_b_1.txt", "set_b_2.txt"])

# Find cross-similarities
cross_matches = mrsh.compare(collection_a, collection_b, threshold=60)

for match in cross_matches:
    print(f"Cross-match: {match.hash1} ↔ {match.hash2}")
```

## Performance Tips

1. **Use appropriate thresholds**: Higher thresholds (70-90) for near-duplicates, lower (30-50) for loose similarity
2. **Batch operations**: Use `fpl` objects for multiple files rather than individual `fp` objects
3. **Memory management**: Objects are automatically cleaned up, but for large datasets consider processing in chunks
4. **File vs bytes**: Direct file processing (`str` paths) is more efficient than loading into memory first

## Error Handling

The library handles most errors gracefully:
- Invalid files return empty results
- Memory allocation failures return `None`  
- Type errors raise `TypeError` exceptions

```python
try:
    fp = mrsh.fp("nonexistent_file.txt")
    result = mrsh.compare(fp1, fp2)
except TypeError as e:
    print(f"Type error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Requirements

- Python 3.6+
- `libmrsh.so` shared library in the package directory
- Compatible C library with all exported functions
