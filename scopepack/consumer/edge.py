"""Download edge (node-a / node-b).

An edge owns a local artifact cache and serves bytes to consumers.  It is a
separate process from both the registry and the builder, and it holds no
consumer tokens beyond the life of a request.

Safety properties exercised here
--------------------------------
* Every data chunk is preceded by a fresh registry authorisation check.  A
  renewal that tightens the purpose therefore terminates an in-flight slow
  download within ``edge_recheck_ms`` instead of letting the old bytes finish.
* Cached artifacts are purged eagerly once the registry reports that their
  policy is no longer current, so an already-issued URL cannot keep serving a
  stale, wider package from cache.
* The edge never trims fields at read time.  It can only serve artifacts that
  were born under an allow-list, and it refuses any artifact whose manifest
  field set differs from the contract it is authorised under.
* A truncated stream is never acknowledged.  Consumers that retry a renewal or
  an acknowledgement with the same key get the original result.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.error
from pathlib import Path
from typing import Any, Iterator

from scopepack.common.config import Settings, load_settings
from scopepack.common.http import ApiError, Request, Service, StreamResponse, http_json, http_open
from scopepack.common.util import (
    append_jsonl,
    atomic_write,
    canonical_json,
    file_lock,
    new_id,
    now_iso,
    sha256_file,
    utcnow,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("scopepack.edge")


class Edge:
    def __init__(self, settings: Settings, node_id: str, cache_dir: Path):
        self.settings = settings
        self.node_id = node_id
        self.cache_dir = cache_dir
        self.artifacts_dir = cache_dir / "artifacts"
        self.manifests_dir = cache_dir / "manifests"
        self.state_path = cache_dir / "state.json"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.active_sessions = 0
        self._session_lock = threading.Lock()
        self._stop = threading.Event()
        self._purger: threading.Thread | None = None

    # ------------------------------------------------------------------ auth
    def require_service(self, req: Request) -> None:
        from scopepack.common.util import safe_equal
        supplied = req.header("X-Service-Token") or (req.bearer() or "")
        if not supplied or not safe_equal(supplied, self.settings.service_token):
            raise ApiError(401, "service_auth_required", "a valid service token is required")

    def registry(self, method: str, path: str, body: Any | None = None, timeout: float = 5.0):
        status, payload = http_json(
            method, self.settings.registry_base + path, body,
            headers={"X-Service-Token": self.settings.service_token}, timeout=timeout,
        )
        if status >= 400:
            message = payload.get("error", {}).get("message") if isinstance(payload, dict) else str(payload)
            code = payload.get("error", {}).get("code") if isinstance(payload, dict) else "registry_error"
            raise ApiError(status, code or "registry_error", message or "registry request failed", payload)
        return payload

    def event(self, grant_id: str, event: str, bytes_sent: int = 0, detail: str = "") -> None:
        try:
            self.registry("POST", "/edge/v1/events", {
                "grant_id": grant_id, "node_id": self.node_id,
                "event": event, "bytes": bytes_sent, "detail": detail,
            }, timeout=2.0)
        except (ApiError, urllib.error.URLError, OSError):
            log.warning("could not report event %s for %s", event, grant_id)
        append_jsonl(self.cache_dir / "events.log", {
            "at": now_iso(), "grant_id": grant_id, "event": event,
            "bytes": bytes_sent, "detail": detail,
        })

    # ----------------------------------------------------------------- cache
    def cached_paths(self, package_key: str) -> tuple[Path, Path]:
        return self.artifacts_dir / f"{package_key}.ndjson", self.manifests_dir / f"{package_key}.json"

    def _load_state(self) -> dict[str, Any]:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"packages": {}}

    def _save_state(self, state: dict[str, Any]) -> None:
        atomic_write(self.state_path, json.dumps(state, indent=2, sort_keys=True).encode())

    def touch_cache(self, package_key: str, metadata: dict[str, Any]) -> None:
        with file_lock(self.cache_dir / ".state.lock"):
            state = self._load_state()
            state.setdefault("packages", {})[package_key] = metadata | {"cached_at": now_iso()}
            self._save_state(state)

    def cache_bytes(self) -> tuple[int, int]:
        total = 0
        count = 0
        for path in self.artifacts_dir.glob("*.ndjson"):
            try:
                total += path.stat().st_size
                count += 1
            except OSError:
                pass
        return total, count

    def fetch_to_cache(self, package_key: str, expected_sha: str, expected_size: int,
                       manifest: dict[str, Any], signature: str) -> Path:
        # Concurrent downloads for the same package share one prefetch.
        with file_lock(self.cache_dir / f".fetch-{package_key}.lock"):
            return self._fetch_to_cache(package_key, expected_sha, expected_size, manifest, signature)

    def _fetch_to_cache(self, package_key: str, expected_sha: str, expected_size: int,
                        manifest: dict[str, Any], signature: str) -> Path:
        artifact_path, manifest_path = self.cached_paths(package_key)
        if artifact_path.exists():
            sha, size = sha256_file(artifact_path)
            if sha == expected_sha and size == expected_size:
                return artifact_path
            log.warning("cache digest mismatch for %s; refetching", package_key)
            artifact_path.unlink(missing_ok=True)
        tmp = self.cache_dir / f".{package_key}.{new_id('dl')[:8]}.partial"
        url = f"{self.settings.builder_base}/artifacts/{package_key}"
        digest = hashlib.sha256()
        size = 0
        try:
            with http_open(url, headers={"X-Service-Token": self.settings.service_token},
                           timeout=30) as response, tmp.open("wb") as out:
                while True:
                    block = response.read(1 << 16)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
            if digest.hexdigest() != expected_sha:
                raise ApiError(502, "upstream_digest_mismatch",
                               "builder artifact digest does not match the registry manifest")
            if expected_size and size != expected_size:
                raise ApiError(502, "upstream_size_mismatch", "builder artifact size does not match")
            os.replace(tmp, artifact_path)
        finally:
            tmp.unlink(missing_ok=True)
        atomic_write(manifest_path, canonical_json(manifest).encode("utf-8"))
        self.touch_cache(package_key, {
            "sha256": expected_sha, "size_bytes": expected_size,
            "signature": signature, "manifest": manifest,
        })
        return artifact_path

    def purge_package(self, package_key: str, reason: str) -> None:
        artifact_path, manifest_path = self.cached_paths(package_key)
        removed = False
        for path in (artifact_path, manifest_path):
            if path.exists():
                path.unlink(missing_ok=True)
                removed = True
        with file_lock(self.cache_dir / ".state.lock"):
            state = self._load_state()
            state.get("packages", {}).pop(package_key, None)
            state.setdefault("purges", []).append(
                {"package_key": package_key, "reason": reason, "at": now_iso()})
            state["purges"] = state["purges"][-100:]
            self._save_state(state)
        if removed:
            log.warning("purged cache for %s: %s", package_key, reason)
            append_jsonl(self.cache_dir / "events.log", {
                "at": now_iso(), "grant_id": "", "event": "cache_purged",
                "bytes": 0, "detail": f"{package_key}: {reason}",
            })

    def start_purger(self) -> None:
        self._purger = threading.Thread(target=self._purge_loop, name="edge-purger", daemon=True)
        self._purger.start()

    def stop(self) -> None:
        self._stop.set()
        if self._purger:
            self._purger.join(timeout=5)

    def _purge_loop(self) -> None:
        while not self._stop.wait(2.0):
            state = self._load_state()
            for package_key in list(state.get("packages", {})):
                info = self.package_state(package_key)
                if info.get("code") == "state_unavailable":
                    continue
                if not info.get("downloadable"):
                    self.purge_package(package_key, str(info.get("code") or "not_downloadable"))
            self.heartbeat()

    def heartbeat(self) -> None:
        total, count = self.cache_bytes()
        try:
            self.registry("POST", "/edge/v1/nodes/heartbeat", {
                "node_id": self.node_id,
                "name": f"Download edge {self.node_id}",
                "base_url": f"http://127.0.0.1:{self.settings.node_a_port if self.node_id == 'node-a' else self.settings.node_b_port}",
                "cache_bytes": total, "cached_packages": count,
                "last_error": "",
            }, timeout=2.0)
        except (ApiError, urllib.error.URLError, OSError):
            pass

    # ------------------------------------------------------------- download
    def start_download(self, req: Request) -> StreamResponse:
        body = req.body()
        grant_id = body.get("grant_id")
        if not isinstance(grant_id, str) or not grant_id:
            raise ApiError(422, "invalid_grant", "grant_id is required")
        consumer_token = req.bearer()
        if not consumer_token:
            raise ApiError(401, "consumer_auth_required", "a subscription bearer token is required")
        decision = self.registry("POST", "/edge/v1/authorize", {
            "grant_id": grant_id, "consumer_token": consumer_token, "node_id": self.node_id,
        })
        if decision.get("decision") != "allow":
            raise ApiError(403, decision.get("code") or "denied",
                           decision.get("reason") or "download is not authorized",
                           {"retain_artifact": decision.get("retain_artifact", False)})
        contract = decision["contract"]
        package = decision["package"]
        package_key = package["package_key"]
        manifest_fields = [f["name"] for f in package["manifest"]["fields"]]
        if manifest_fields != contract["allowed_fields"]:
            self.event(grant_id, "manifest_contract_mismatch",
                       detail="manifest fields differ from the contract allow-list")
            raise ApiError(409, "manifest_contract_mismatch",
                           "cached package manifest does not match the contract allow-list")
        try:
            artifact_path = self.fetch_to_cache(
                package_key, package["content_sha256"], int(package["size_bytes"] or 0),
                package["manifest"], package["signature"] or "")
        except ApiError:
            self.event(grant_id, "cache_fetch_failed", detail="builder artifact unavailable")
            raise
        # Prefetching can take time.  Re-check before writing any bytes: a
        # package retired while we were fetching must not be served.
        ok, code, reason = self.recheck(grant_id, consumer_token, package_key)
        if not ok:
            self.purge_package(package_key, code)
            self.event(grant_id, "prefetch_authorization_lost", detail=f"{code}: {reason}")
            raise ApiError(403, code, f"authorization withdrawn before streaming: {reason}")
        if not artifact_path.exists():
            raise ApiError(410, "artifact_gone", "package artifact is not available")
        size = artifact_path.stat().st_size
        range_header = req.header("Range")
        start = 0
        if range_header:
            match = re.fullmatch(r"bytes=(\d+)-(\d*)", range_header.strip())
            if not match:
                raise ApiError(416, "invalid_range", "only single open-ended byte ranges are supported")
            start = int(match.group(1))
            if start >= size:
                raise ApiError(416, "range_not_satisfiable", "range starts beyond the artifact",
                               {"size": size})
        length = size - start
        with self._session_lock:
            self.active_sessions += 1
        session = {
            "grant_id": grant_id, "package_key": package_key,
            "consumer_id": decision["consumer"]["consumer_id"],
            "started_at": now_iso(), "start_offset": start, "sent": 0,
            "aborted": False, "finished": False, "reason": "",
        }
        artifact = artifact_path

        def chunks() -> Iterator[bytes]:
            nonlocal session
            sent = 0
            last_check = 0.0
            cursor = start
            handle = artifact.open("rb")
            try:
                handle.seek(start)
                while cursor < size:
                    now = time.monotonic()
                    if now - last_check >= self.settings.edge_recheck_ms / 1000.0:
                        last_check = now
                        ok, code, reason = self.recheck(grant_id, consumer_token, package_key)
                        if not ok:
                            session["aborted"] = True
                            session["reason"] = f"{code}: {reason}"
                            # Purge immediately when the package itself is no longer
                            # deliverable.  A revoked grant alone (e.g. a contract
                            # superseded but with the same artifact) is not enough to
                            # evict a still-valid cache entry.
                            if code != "grant_revoked":
                                self.purge_package(package_key, code)
                            else:
                                state = self.package_state(package_key)
                                if not state.get("downloadable", False):
                                    self.purge_package(package_key, str(state.get("code") or code))
                            raise RuntimeError(f"authorization withdrawn mid-stream ({code}): {reason}")
                    block = handle.read(min(self.settings.edge_chunk_bytes, size - cursor))
                    if not block:
                        break
                    cursor += len(block)
                    sent += len(block)
                    session["sent"] = sent
                    yield block
                    delay = self.settings.edge_chunk_delay_ms / 1000.0
                    if delay:
                        time.sleep(delay)
                if cursor < size:
                    raise RuntimeError("artifact truncated while streaming")
                session["finished"] = True
            finally:
                handle.close()

        def complete() -> None:
            with self._session_lock:
                self.active_sessions = max(0, self.active_sessions - 1)
            self.event(grant_id, "stream_complete", session["sent"],
                       f"package={package_key} offset={start} bytes={length}")
            self.touch_cache(package_key, {
                "sha256": package["content_sha256"], "size_bytes": int(package["size_bytes"] or 0),
                "signature": package["signature"] or "", "manifest": package["manifest"],
            })

        def abort(reason: str) -> None:
            with self._session_lock:
                self.active_sessions = max(0, self.active_sessions - 1)
            detail = session["reason"] or reason
            self.event(grant_id, "stream_aborted", session["sent"],
                       f"package={package_key} offset={start} reason={detail}")
            if session["aborted"]:
                log.warning("download aborted mid-stream package=%s grant=%s reason=%s",
                            package_key, grant_id, detail)

        headers = {
            "X-Package-Key": package_key,
            "X-Package-Sha256": package["content_sha256"],
            "X-Package-Signature": package["signature"] or "",
            "X-Package-Fields": ",".join(contract["allowed_fields"]),
            "X-Contract-Version": str(contract["version"]),
            "X-Authz-Checked-At": decision.get("checked_at") or now_iso(),
            "Accept-Ranges": "bytes",
        }
        status = 200
        if start:
            status = 206
            headers["Content-Range"] = f"bytes {start}-{size - 1}/{size}"
        return StreamResponse(status, "application/x-ndjson", length, chunks(),
                              headers=headers, on_complete=complete, on_abort=abort)

    def package_state(self, package_key: str) -> dict[str, Any]:
        try:
            return self.registry("GET", f"/edge/v1/packages/{package_key}/state", timeout=2.0)
        except (ApiError, urllib.error.URLError, OSError):
            return {"downloadable": False, "code": "state_unavailable"}

    def recheck(self, grant_id: str, consumer_token: str, package_key: str) -> tuple[bool, str, str]:
        """Cheap authorisation probe.  Returns (allowed, code, reason)."""
        try:
            payload = self.registry("POST", "/edge/v1/authorize", {
                "grant_id": grant_id, "consumer_token": consumer_token,
                "node_id": self.node_id, "probe": True,
            }, timeout=3.0)
        except (ApiError, urllib.error.URLError, OSError) as exc:
            # Fail closed: a slow download may not outlive the registry's ability
            # to confirm that the contract is still current.
            return False, "authorization_unavailable", f"registry check failed: {exc}"
        if payload.get("decision") == "allow":
            if payload["package"]["package_key"] != package_key:
                return False, "package_mismatch", "grant now points at a different package"
            return True, "allowed", "ok"
        return False, str(payload.get("code") or "denied"), str(payload.get("reason") or "denied")


EDGE: Edge


def register_routes(service: Service, edge: Edge) -> None:
    @service.get("/healthz")
    def health(_: Request):
        total, count = edge.cache_bytes()
        return {"status": "ok", "service": "edge", "node_id": edge.node_id,
                "cache_bytes": total, "cached_packages": count,
                "active_sessions": edge.active_sessions, "now": now_iso()}

    @service.post("/downloads")
    def downloads(req: Request):
        return edge.start_download(req)

    @service.get("/admin/cache")
    def admin_cache(req: Request):
        edge.require_service(req)
        state = edge._load_state()
        return {"node_id": edge.node_id, "state": state,
                "bytes": edge.cache_bytes()[0], "packages": edge.cache_bytes()[1]}

    @service.get("/admin/sessions")
    def admin_sessions(req: Request):
        edge.require_service(req)
        return {"node_id": edge.node_id, "active": edge.active_sessions}

    @service.get("/admin/purge")
    def admin_purge(req: Request):
        edge.require_service(req)
        key = req.q("package_key")
        if key:
            edge.purge_package(key, "manual")
        return {"status": "ok", "package_key": key}


def main(argv: list[str] | None = None) -> int:
    global EDGE
    argv = argv if argv is not None else sys.argv[1:]
    node_id = "node-a"
    if "--node-id" in argv:
        node_id = argv[argv.index("--node-id") + 1]
    if node_id not in ("node-a", "node-b"):
        print("node-id must be node-a or node-b", file=sys.stderr)
        return 2
    settings = load_settings()
    port = settings.node_a_port if node_id == "node-a" else settings.node_b_port
    cache_dir = settings.edges_dir / node_id
    cache_dir.mkdir(parents=True, exist_ok=True)
    EDGE = Edge(settings, node_id, cache_dir)
    EDGE.start_purger()
    service = Service(f"edge-{node_id}", port)
    register_routes(service, EDGE)
    service.serve_forever()
    EDGE.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
