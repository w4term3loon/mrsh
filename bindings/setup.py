from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

setup(
    name="mrshw",
    version="0.1.0b4",
    author="w4term3loon",
    author_email="ifkovics.barnabas@gmail.com",
    description="Python bindings for MRSH: a fast, modular similarity digest tool for malware analysis",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={
        "mrshw": ["libmrsh.so"],
    },
    include_package_data=True,
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
    keywords="similarity hashing, malware detection, sdhash, tlsh, binary analysis, ctypes, python bindings",
    license_files=["LICENSE"]
)

