from dataclasses import dataclass
from pathlib import Path
from security.hashing.hash_service import sha256_file

@dataclass(frozen=True)
class IntegrityResult:
    filename: str
    actual_hash: str
    expected_hash: str | None
    verified: bool
    status: str

def verify_file(path: str | Path, expected_hash: str | None = None):
    p = Path(path)
    actual = sha256_file(p)
    if expected_hash is None:
        return IntegrityResult(p.name, actual, None, False, "HASH_GENERATED")
    valid = actual.lower() == expected_hash.strip().lower()
    return IntegrityResult(p.name, actual, expected_hash, valid, "VERIFIED" if valid else "MISMATCH")
