from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.1.0",
    description="AES-128 ECB/CBC/CFB/OFB/CTR encryption/decryption and SHA-256/SHA3-256 hashing CLI tool",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "pycryptodome>=3.19",
    ],
    entry_points={
        "console_scripts": [
            "cryptocore=src.main:main",
        ],
    },
    python_requires=">=3.8",
)
