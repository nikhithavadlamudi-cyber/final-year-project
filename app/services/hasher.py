"""
SHA-256 Streaming Hasher Service
─────────────────────────────────
Why streaming?
  Real memory images are typically 1–32 GB.
  Loading the entire file into RAM before hashing would crash the server.
  Instead, we read the file in small chunks (default 1 MB) and feed each
  chunk to the hash object one at a time — using almost no extra RAM.

How it works (beginner explanation):
  hashlib.sha256() creates an empty "running total" for the hash.
  Each time we call update(chunk), Python adds that piece of data to the total.
  When we call hexdigest() at the end, we get the final 64-character hex hash.
"""
import hashlib
from pathlib import Path
from app.config import HASH_CHUNK_SIZE


def compute_sha256(file_path: Path) -> str:
    """
    Reads a file in HASH_CHUNK_SIZE chunks and returns its SHA-256 hex digest.

    Args:
        file_path: Absolute Path to the file on disk.

    Returns:
        64-character lowercase hexadecimal string (the SHA-256 hash).

    Raises:
        FileNotFoundError: If the file does not exist at the given path.
        IOError: If the file cannot be read.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256 = hashlib.sha256()

    # Open in binary mode — memory images are raw binary, not text.
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK_SIZE)   # read up to 1 MB
            if not chunk:
                break                           # end of file
            sha256.update(chunk)               # feed chunk into hash

    return sha256.hexdigest()   # e.g. "3b4c5d..."


def compute_sha256_from_bytes(data: bytes) -> str:
    """
    Computes SHA-256 from raw bytes (used during upload before the file is saved).

    Args:
        data: Raw bytes of the file (OK for small test files).

    Returns:
        64-character lowercase hexadecimal SHA-256 string.
    """
    return hashlib.sha256(data).hexdigest()
