"""Native build configuration for the :mod:`mrshw` package."""

import sys
from pathlib import Path

from setuptools import Extension, setup


ROOT = Path(__file__).parent.resolve()

SOURCES = [
    "src/util.c",
    "src/hashing.c",
    "src/bloomfilter.c",
    "src/fingerprint.c",
    "src/fingerprintList.c",
    "src/helper.c",
    "src/traversal.c",
    "bindings/glue/mrsh_glue.c",
]
HEADERS = [
    str(path.relative_to(ROOT))
    for path in sorted((ROOT / "header").glob("*.h"))
] + ["bindings/glue/mrsh_glue.h"]


setup(
    ext_modules=[
        Extension(
            "mrshw.libmrsh",
            sources=SOURCES,
            depends=HEADERS,
            include_dirs=[str(ROOT / "header")],
            define_macros=[("_DEFAULT_SOURCE", "1")],
            libraries=["m"],
            extra_compile_args=[
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wmissing-prototypes",
                "-fvisibility=hidden",
            ],
            extra_link_args=(
                ["-Wl,-Bsymbolic-functions"]
                if sys.platform.startswith("linux")
                else []
            ),
        )
    ]
)
