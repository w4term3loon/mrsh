# Changelog

## 1.1.0 (unreleased)

### Security

- Bound and validate all path, label, digest, list, and numeric input before use.
- Initialize empty fingerprints and propagate allocation and I/O failures rather
  than terminating the host Python process.
- Correct native ownership, deep-copy, parser, descriptor, and directory-scanning
  behavior that could cause overflows, overreads, use-after-free, leaks, or
  process-wide state changes.
- Bound lists to 100,000 entries and 256 MiB of serialized data. Reject
  comparison workloads over 1,000,000 candidate or aggregate Bloom-filter
  pairs before scoring, and bound results to 1,000,000 records and 256 MiB of
  copied labels. Preflight native CLI comparison output against a 256 MiB cap
  so oversized results cannot produce partial output or disk amplification.
- Use descriptor-relative, identity-verified directory traversal so concurrent
  intermediate-component symlink swaps or symlinks in supplied roots cannot
  redirect scans.
- Bound extension iterables and nested/shared Python input graphs; reject
  container cycles without recursion or partial list updates.
- Reject terminal control bytes in serialized and path-derived labels.
- Identity-check the opened target of an accepted top-level file symlink and
  escape untrusted paths in native error output.

### Changed

- Define scores and thresholds consistently as 0–100, with 100 identical.
- Add explicit `close()`/context-manager ownership and strict digest constructors.
- Stream file content to EOF, including size-zero virtual regular files, while
  preserving digest compatibility and recording actual 64-bit byte counts.
- Use `mrshw` consistently as both distribution and import name; retain `mrsh` as
  the command name.
- Build the native library from source through a root `pyproject.toml` and emit
  platform wheels rather than a false `py3-none-any` artifact.
- Remove the unused OpenSSL build dependency.

### Quality

- Add golden-vector, API, malformed-input, ownership, resource-leak, CLI, and
  directory regression tests.
- Add strict compiler warnings, sanitizer CI, distribution validation, and
  x86-64/AArch64 manylinux wheel builds.
