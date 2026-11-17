"""Small, dependency-free helpers used by every service."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso(dt: datetime | None = None) -> str:
    value = dt or utcnow()
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_after(seconds: float) -> str:
    return now_iso(utcnow() + timedelta(seconds=seconds))


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def is_past(value: str | None) -> bool:
    if not value:
        return True
    try:
        return parse_iso(value) <= utcnow()
    except (TypeError, ValueError):
        return True


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, block_size: int = 1 << 20) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(block_size)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def hmac_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def safe_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def token_hash(token: str) -> str:
    return sha256_text(token)


def new_token(prefix: str = "sp") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def redact_token(token: str) -> str:
    if len(token) <= 10:
        return token[:2] + "***"
    return token[:7] + "…" + token[-4:]


def read_json_body(handler, limit: int = 1_000_000) -> dict[str, Any]:
    length = handler.headers.get("Content-Length")
    if length is None:
        return {}
    try:
        size = int(length)
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc
    if size < 0 or size > limit:
        raise ValueError("request body too large")
    raw = handler.rfile.read(size)
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON body") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(value) + "\n")


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Advisory lock for the tiny per-node state files."""
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
