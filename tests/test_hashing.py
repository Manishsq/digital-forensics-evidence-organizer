"""
Tests for the hashing service.

Verifies SHA-256, SHA-512 and MD5 against known values.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest


def test_sha256_known_value(tmp_path):
    """SHA-256 of empty file equals the well-known value."""
    from app.services.hashing import calculate_hashes
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = calculate_hashes(f)
    assert result["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha512_known_value(tmp_path):
    """SHA-512 of empty file equals the well-known value."""
    from app.services.hashing import calculate_hashes
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = calculate_hashes(f)
    assert result["sha512"] == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )


def test_md5_known_value(tmp_path):
    """MD5 of empty file equals the well-known value."""
    from app.services.hashing import calculate_hashes
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = calculate_hashes(f)
    assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_sha256_non_empty(tmp_path):
    """SHA-256 of 'hello world' matches expected digest."""
    from app.services.hashing import calculate_hashes
    f = tmp_path / "hw.txt"
    f.write_bytes(b"hello world")
    result = calculate_hashes(f)
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert result["sha256"] == expected


def test_sha512_non_empty(tmp_path):
    from app.services.hashing import calculate_hashes
    f = tmp_path / "hw.txt"
    f.write_bytes(b"hello world")
    result = calculate_hashes(f)
    expected = hashlib.sha512(b"hello world").hexdigest()
    assert result["sha512"] == expected


def test_md5_non_empty(tmp_path):
    from app.services.hashing import calculate_hashes
    f = tmp_path / "hw.txt"
    f.write_bytes(b"hello world")
    result = calculate_hashes(f)
    expected = hashlib.md5(b"hello world").hexdigest()
    assert result["md5"] == expected


def test_hashes_dict_keys(tmp_path):
    """calculate_hashes returns dict with all three keys."""
    from app.services.hashing import calculate_hashes
    f = tmp_path / "test.bin"
    f.write_bytes(b"test data")
    result = calculate_hashes(f)
    assert set(result.keys()) == {"sha256", "sha512", "md5"}


def test_hashes_large_file(tmp_path):
    """Hashing a >1 MB file (multi-chunk) produces correct SHA-256."""
    from app.services.hashing import calculate_hashes
    data = b"A" * (2 * 1024 * 1024)  # 2 MB
    f = tmp_path / "large.bin"
    f.write_bytes(data)
    result = calculate_hashes(f)
    expected = hashlib.sha256(data).hexdigest()
    assert result["sha256"] == expected


def test_calculate_sha256_standalone(tmp_path):
    from app.services.hashing import calculate_sha256
    f = tmp_path / "t.txt"
    f.write_bytes(b"standalone")
    assert calculate_sha256(f) == hashlib.sha256(b"standalone").hexdigest()


def test_file_not_found():
    from app.services.hashing import calculate_hashes
    with pytest.raises(FileNotFoundError):
        calculate_hashes(Path("/nonexistent/file.bin"))
