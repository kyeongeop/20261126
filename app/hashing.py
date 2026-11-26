"""Content hashing helpers for stable source locators.

Every locator pins two hashes:

* ``content_hash``  - hash of the exact bytes the locator was created from
  (a whole line, or the byte span at an offset).
* ``file_hash``     - hash of the whole source file at creation time.

On resolution, hashes are compared exactly. If anything changed, the
locator is reported as ``stale`` instead of being re-anchored at a
similar-looking position.
"""

from __future__ import annotations

import hashlib

HASH_ALGORITHM = "sha256"
HASH_PREFIX_LENGTH = 12


def hash_bytes(data: bytes) -> str:
    """Return the full hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def shorten(full_hash: str, length: int = HASH_PREFIX_LENGTH) -> str:
    """Return the short, display- and URL-friendly hash prefix."""
    return full_hash[:length]


def verify_prefix(full_hash: str, prefix: str) -> bool:
    """True when ``prefix`` is a prefix of ``full_hash`` (case-insensitive)."""
    if not prefix:
        return False
    return full_hash.lower().startswith(prefix.lower())
