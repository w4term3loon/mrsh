# Security policy

## Supported versions

The maintained development line is 1.1.x, which is not yet published. Version
1.0.0 is the only current PyPI release; it contains known native memory-safety,
parser, ownership, and packaging defects and must not be used with untrusted
files or digests.

## Reporting a vulnerability

Please report security issues privately to the maintainer at
`ifkovics.barnabas@gmail.com`. Include the affected version, platform, a minimal
reproducer, and sanitizer output when available. Do not attach sensitive sample
data or publish a proof of concept before a fix is available.

## Scope and expectations

MRSH computes similarity indicators; it does not authenticate content and is
not a cryptographic hash. Callers must not use a score—even 100—as the sole basis
for a security-sensitive identity decision.

Hashing has constant memory overhead but necessarily performs work linear in
the bytes read and intentionally supports large files. Applications accepting
adversary-controlled storage must enforce appropriate file-size, aggregate-I/O,
and process-time budgets outside this library.

The test suite exercises malformed digest input and native code under Address-
Sanitizer and UndefinedBehaviorSanitizer. These checks reduce risk but do not
constitute a guarantee that the implementation is vulnerability-free.
