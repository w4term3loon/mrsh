"""
Setup script for MRSHw package.
"""

import sys
import pathlib
from setuptools import setup

here = pathlib.Path(__file__).parent.resolve()

# block installation on non-Linux systems
if not sys.platform.startswith("linux"):
    raise RuntimeError(
        f"mrshw requires a Linux environment and does not support '{sys.platform}'."
    )

setup(
    name="mrshw",
    version="1.0.0",
    author="w4term3loon",
    author_email="ifkovics.barnabas@gmail.com",
    description="Python bindings for MRSHv2: modular similarity digest tool for malware analysis, forensics and much more",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    packages=["mrsh"],
    include_package_data=True,
    package_dir={"mrsh": "mrshw"},
    package_data={
        "mrsh": ["libmrsh.so"],
    },
    entry_points={
        'console_scripts': [
            'mrsh=mrsh.cli:main',
        ],
    },
    url="https://github.com/w4term3loon/mrsh",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: C",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Topic :: Utilities",
    ],
    project_urls={
        "Documentation": "https://github.com/w4term3loon/mrsh",
        "Source": "https://github.com/w4term3loon/mrsh",
        "Bug Tracker": "https://github.com/w4term3loon/mrsh/issues",
    },
    python_requires=">=3.7",
    keywords="binary, analysis, python, binding, malware, hashing, similarity, detection, security, digital, forensics",
    license_files=["LICENSE"]
)

