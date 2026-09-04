# Contributing

Use a supported Python version and a C99 compiler. Create an isolated environment
and install the project from its repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m pytest
make
```

Keep native entry points failure-atomic: validate input first, return an
`MRSH_STATUS` error, and leave caller-owned objects valid. Do not call `exit()`
from library code or expose ownership of internal pointers. New parser and
ownership fixes should include a regression test that fails under the relevant
sanitizer before the fix.

Before preparing a release, build and inspect both formats:

```bash
python -m pip install ".[release]"
python -m build
python -m twine check dist/*
python tools/check_dist.py dist
```

Release artifacts are built by the tag-triggered workflow but are deliberately
not uploaded to PyPI automatically.
