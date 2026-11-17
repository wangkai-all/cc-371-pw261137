"""Package builder service (port 7102).

The builder is a separate process and a separate security principal.  It leases
one job at a time from the registry, reads the fictional source, emits only the
leased field set as NDJSON, and reports the content hash back.  If its lease
expires before completion another builder may take the job; completion is
guarded by the lease token and becomes idempotent once the job is done.

The builder also serves finished artifacts to download edges.  Edge nodes pull
the bytes at the digest the registry published, verify them, and only then put
them in their cache.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
from pathlib import Path
from typing import Any

from scopepack.common.config import Settings, load_settings
from scopepack.common.db import connect
from scopepack.common.http import ApiError, JsonResponse, Request, Service, StreamResponse, http_json
from scopepack.common.policy import (
    FIELD_CATALOG,
    FIELD_ORDER,
    build_manifest,
    policy_decision,
)
from scopepack.common.util import (
    append_jsonl,
    atomic_write,
    canonical_json,
    new_id,
    now_iso,
    sha256_bytes,
    sha256_file,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("scopepack.builder")

BUILD_LOCK = threading.Lock()


class Builder:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.owner = os.environ.get("SCOPEPACK_BUILDER_NAME") or f"builder-{os.getpid()}"
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.current: dict[str, Any] | None = None
        self.stats = {"built": 0, "failed": 0, "lease_conflicts": 0, "started_at": now_iso()}
        self._state_lock = threading.Lock()

    # ------------------------------------------------------------------ auth
    def require_service(self, req: Request) -> None:
        from scopepack.common.util import safe_equal
        supplied = req.header("X-Service-Token") or (req.bearer() or "")
        if not supplied or not safe_equal(supplied, self.settings.service_token):
            raise ApiError(401, "service_auth_required", "a valid service token is required")

    def call(self, method: str, path: str, body: Any | None = None, timeout: float = 10.0):
        status, payload = http_json(
            method, self.settings.registry_base + path, body,
            headers={"X-Service-Token": self.settings.service_token}, timeout=timeout,
        )
        if status >= 400:
            message = payload.get("error", {}).get("message") if isinstance(payload, dict) else str(payload)
            code = payload.get("error", {}).get("code") if isinstance(payload, dict) else "error"
            raise ApiError(status, code or "registry_error", message or "registry request failed", payload)
        return payload

    # ---------------------------------------------------------------- worker
    def start(self) -> None:
        self.settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.worker = threading.Thread(target=self._loop, name="builder-worker", daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=10)

    def _loop(self) -> None:
        backoff = 0.2
        while not self.stop_event.is_set():
            try:
                payload = self.call("POST", "/builder/v1/jobs/lease", {
                    "owner": self.owner,
                    "lease_seconds": self.settings.builder_lease_seconds,
                })
                job = payload.get("job")
                if not job:
                    backoff = 0.2
                    self.stop_event.wait(0.4)
                    continue
                backoff = 0.2
                self._build(job)
            except ApiError as exc:
                log.warning("lease/build error: %s %s", exc.code, exc.message)
                self.stop_event.wait(min(3.0, backoff))
                backoff = min(3.0, backoff * 2)
            except (urllib.error.URLError, OSError) as exc:
                log.warning("registry unreachable: %s", exc)
                self.stop_event.wait(min(3.0, backoff))
                backoff = min(3.0, backoff * 2)
            except Exception:
                log.exception("builder loop crashed; continuing")
                self.stop_event.wait(1.0)

    def _heartbeat(self, job: dict[str, Any], stop: threading.Event) -> None:
        while not stop.wait(max(1.0, self.settings.builder_lease_seconds / 3)):
            try:
                self.call("POST", f"/builder/v1/jobs/{job['id']}/heartbeat", {
                    "lease_token": job["lease_token"],
                    "lease_seconds": self.settings.builder_lease_seconds,
                })
            except ApiError as exc:
                log.warning("lease heartbeat rejected job=%s: %s", job["id"], exc.code)
                if exc.code in ("job_not_leased", "lease_conflict"):
                    stop.set()
                    return
            except (urllib.error.URLError, OSError):
                log.warning("heartbeat network error job=%s", job["id"])

    def _build(self, job: dict[str, Any]) -> None:
        with self._state_lock:
            self.current = {"job_id": job["id"], "package_key": job["package_key"],
                            "started_at": now_iso(), "phase": "rendering"}
        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(target=self._heartbeat, args=(job, heartbeat_stop), daemon=True)
        heartbeat.start()
        try:
            delay = int(job.get("build_delay_ms") or 0) / 1000.0
            if delay:
                time.sleep(delay)
            result = self.render_artifact(job)
            if heartbeat_stop.is_set():
                raise ApiError(409, "lease_lost", "lease was lost while rendering; abandoning completion")
            response = self.call("POST", f"/builder/v1/jobs/{job['id']}/complete", result, timeout=30)
            size = int(response["package"]["size_bytes"] or 0)
            self.stats["built"] += 1
            append_jsonl(self.settings.home / "build-log.jsonl", {
                "at": now_iso(), "job_id": job["id"], "package_key": job["package_key"],
                "sha256": result["content_sha256"], "bytes": size, "outcome": "ready",
            })
            log.info("built %s sha=%s bytes=%s", job["package_key"], result["content_sha256"][:12], size)
        except ApiError as exc:
            if exc.code == "lease_conflict":
                self.stats["lease_conflicts"] += 1
                log.warning("lease conflict, another builder completed job=%s", job["id"])
            else:
                self._report_failure(job, exc.message)
        except Exception as exc:
            log.exception("build failed job=%s", job["id"])
            self._report_failure(job, f"{type(exc).__name__}: {exc}")
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=2)
            with self._state_lock:
                self.current = None

    def _report_failure(self, job: dict[str, Any], reason: str) -> None:
        self.stats["failed"] += 1
        try:
            self.call("POST", f"/builder/v1/jobs/{job['id']}/fail", {
                "lease_token": job["lease_token"], "reason": reason,
            })
        except (ApiError, urllib.error.URLError, OSError):
            log.warning("could not report failure for job=%s", job["id"])
        append_jsonl(self.settings.home / "build-log.jsonl", {
            "at": now_iso(), "job_id": job["id"], "package_key": job["package_key"],
            "outcome": "failed", "reason": reason,
        })

    def render_artifact(self, job: dict[str, Any]) -> dict[str, Any]:
        """Render only the leased fields; the artifact never holds anything else."""
        allowed: list[str] = list(job["allowed_fields"])
        unknown = [f for f in allowed if f not in FIELD_CATALOG]
        if unknown:
            raise ApiError(422, "unknown_fields", f"lease contains unknown fields: {unknown}")
        source_label = job["dataset"]["version"]
        source_path = Path(job["source_path"])
        out_dir = self.settings.artifacts_dir / job["package_key"]
        out_dir.mkdir(parents=True, exist_ok=True)
        partial = out_dir / f".{job['package_key']}.{job['lease_token'][:8]}.partial"
        digest = hashlib.sha256()
        rows = 0
        seen_fields: list[str] | None = None
        try:
            with partial.open("wb") as out:
                with source_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        if seen_fields is None:
                            seen_fields = [f for f in FIELD_ORDER if f in record]
                        missing = [f for f in allowed if f not in record]
                        if missing:
                            raise ApiError(422, "source_missing_field",
                                           f"source lacks fields {missing} for package")
                        rendered = canonical_json({field: record[field] for field in allowed})
                        block = (rendered + "\n").encode("utf-8")
                        out.write(block)
                        digest.update(block)
                        rows += 1
                    out.flush()
                    os.fsync(out.fileno())
            if rows == 0:
                raise ApiError(422, "empty_source", "source dataset is empty")
            content_sha = digest.hexdigest()
            final = out_dir / f"{content_sha}.ndjson"
            os.replace(partial, final)
            rules = {r["field"]: r["reason"] for r in job["rules"]}
            excluded: dict[str, str] = {}
            for field in FIELD_ORDER:
                if field in allowed:
                    continue
                excluded[field] = rules.get(field) or policy_decision(allowed, field)[1]
            manifest = build_manifest(
                package_key=job["package_key"],
                purpose_code=job["purpose"]["code"],
                policy_version=job["policy"]["version"],
                policy_hash=job["policy"]["policy_hash"],
                dataset_version=source_label,
                dataset_sha256=job["dataset"]["sha256"],
                row_count=rows,
                allowed_fields=allowed,
                excluded_fields=excluded,
                pseudonymised_fields=["driver_ref", "vehicle_ref"],
            )
            manifest_path = out_dir / f"{content_sha}.manifest.json"
            atomic_write(manifest_path, canonical_json(manifest).encode("utf-8"))
            actual_sha, actual_size = sha256_file(final)
            if actual_sha != content_sha:
                raise ApiError(500, "artifact_corruption", "artifact changed while being written")
            return {
                "lease_token": job["lease_token"],
                "allowed_fields": allowed,
                "content_sha256": content_sha,
                "size_bytes": actual_size,
                "row_count": rows,
                "artifact_path": str(final),
                "manifest": manifest,
            }
        finally:
            if partial.exists():
                partial.unlink(missing_ok=True)

    # -------------------------------------------------------------- artifact
    def artifact_response(self, package_key: str) -> StreamResponse:
        conn = connect(self.settings.db_path, readonly=True)
        try:
            row = conn.execute(
                "SELECT * FROM packages WHERE package_key=? AND status='ready'", (package_key,)
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row["artifact_path"]:
            raise ApiError(404, "artifact_not_found", "no ready artifact for that package")
        path = Path(row["artifact_path"])
        if not path.exists():
            raise ApiError(410, "artifact_gone", "artifact file is missing from the builder store")
        expected = row["content_sha256"]
        digest = hashlib.sha256()
        size = 0

        def chunks():
            nonlocal size
            with path.open("rb") as handle:
                while True:
                    block = handle.read(1 << 16)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    yield block

        def verify() -> None:
            if digest.hexdigest() != expected:
                log.error("artifact digest changed on disk: %s", package_key)

        return StreamResponse(
            200, "application/x-ndjson", int(row["size_bytes"] or path.stat().st_size),
            chunks(),
            headers={
                "X-Package-Key": package_key,
                "X-Package-Sha256": expected or "",
                "X-Package-Signature": row["signature"] or "",
                "X-Package-Fields": row["fields_hash"] or "",
            },
            on_complete=verify,
        )


BUILDER: Builder


def register_routes(service: Service) -> None:
    @service.get("/healthz")
    def health(_: Request):
        with BUILDER._state_lock:
            current = BUILDER.current
        return {"status": "ok", "service": "builder", "owner": BUILDER.owner,
                "current": current, "stats": BUILDER.stats, "now": now_iso()}

    @service.get(r"/artifacts/(?P<key>[A-Za-z0-9._-]+)")
    def artifact(req: Request):
        BUILDER.require_service(req)
        return BUILDER.artifact_response(req.param("key"))

    @service.post("/builder/v1/wake")
    def wake(req: Request):
        BUILDER.require_service(req)
        return {"status": "ok", "note": "builder polls continuously; wake is advisory"}


def main() -> int:
    global BUILDER
    settings = load_settings()
    BUILDER = Builder(settings)
    BUILDER.start()
    service = Service("builder", settings.builder_port)
    register_routes(service)
    service.serve_forever()
    BUILDER.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
