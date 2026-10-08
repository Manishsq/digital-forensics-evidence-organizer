"""
Cryptographic hashing service.

Uses streaming/chunked reads so large evidence files never
load entirely into RAM.  Supports SHA-256, SHA-512 and MD5
(MD5 retained for legacy forensic comparison only).
"""

import hashlib
from pathlib import Path
from typing import BinaryIO

from app.config import get_settings

settings = get_settings()

CHUNK_SIZE = settings.hash_chunk_size  # 1 MB


def calculate_hashes(file_path: Path) -> dict[str, str]:
    """
    Calculate MD5, SHA-256 and SHA-512 of a file using chunked reads.

    Returns:
        {
            "md5":    "<hex>",
            "sha256": "<hex>",
            "sha512": "<hex>",
        }

    Raises:
        FileNotFoundError: if *file_path* does not exist.
        PermissionError:   if the file cannot be opened for reading.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(file_path, "rb") as fh:
        _hash_stream(fh, [md5, sha256, sha512])

    return {
        "md5":    md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def calculate_sha256(file_path: Path) -> str:
    """Return the SHA-256 hex digest of *file_path*."""
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        _hash_stream(fh, [h])
    return h.hexdigest()


def hash_string(value: str) -> str:
    """Return SHA-256 hex digest of an arbitrary string (UTF-8 encoded)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_stream(fh: BinaryIO, hashers: list) -> None:
    """Feed a file handle into one or more hashlib objects in chunks."""
    while chunk := fh.read(CHUNK_SIZE):
        for h in hashers:
            h.update(chunk)
