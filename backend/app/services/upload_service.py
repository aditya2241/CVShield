from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import HTTPException, UploadFile

from app.core.config import settings

CHUNK_SIZE = 1024 * 1024
SAMPLE_SIZE = 1024 * 1024


async def stream_upload(file: UploadFile) -> tuple[Path, int, str, bytes]:
    """Stream an upload to disk while hashing it; never executes the artifact."""
    limit = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    total = 0
    sample = bytearray()
    tmp_path: Path | None = None

    try:
        with NamedTemporaryFile(prefix="tg-", suffix=".upload", dir=upload_dir, delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB limit")
                digest.update(chunk)
                if len(sample) < SAMPLE_SIZE:
                    sample.extend(chunk[: SAMPLE_SIZE - len(sample)])
                tmp.write(chunk)
            tmp.flush()
            os.fsync(tmp.fileno())

        final_path = upload_dir / f"{digest.hexdigest()}.bin"
        if final_path.exists():
            tmp_path.unlink(missing_ok=True)
        else:
            tmp_path.replace(final_path)
        return final_path, total, digest.hexdigest(), bytes(sample)
    except Exception:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
        raise
