import hashlib
import hmac
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def make_provenance_signature(record: dict, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical_json(record), hashlib.sha256).hexdigest()


def verify_provenance_signature(record: dict, signature: str, secret: str) -> bool:
    expected = make_provenance_signature(record, secret)
    return hmac.compare_digest(expected, signature)
