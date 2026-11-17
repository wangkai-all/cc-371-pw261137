"""Integration harness: boots all four services on ephemeral ports.

The registry, builder and both download edges are started as *separate
processes*, mirroring the production split.  Tests then drive them over HTTP.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "test-admin-token"
SERVICE = "test-service-token"
PEPPER = "test-pepper"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(method: str, url: str, body: Any | None = None, headers: dict[str, str] | None = None,
         timeout: float = 20.0) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, raw.decode("utf-8", "replace")


class Cluster:
    def __init__(self, *, grant_ttl: int = 120, chunk_bytes: int = 4096,
                 chunk_delay_ms: int = 0, recheck_ms: int = 120,
                 build_delay_ms: int = 0, lease_seconds: int = 8):
        self.home = Path(tempfile.mkdtemp(prefix="scopepack-test-"))
        self.registry_port = free_port()
        self.builder_port = free_port()
        self.node_a_port = free_port()
        self.node_b_port = free_port()
        self.base = f"http://127.0.0.1:{self.registry_port}"
        self.builder_base = f"http://127.0.0.1:{self.builder_port}"
        self.node_a = f"http://127.0.0.1:{self.node_a_port}"
        self.node_b = f"http://127.0.0.1:{self.node_b_port}"
        self.grant_ttl = grant_ttl
        self.chunk_delay_ms = chunk_delay_ms
        self.procs: dict[str, subprocess.Popen] = {}
        self.logs: dict[str, Path] = {}
        self.handles: list = []
        self.env = self._env(chunk_bytes, chunk_delay_ms, recheck_ms, build_delay_ms, lease_seconds)

    def _env(self, chunk_bytes: int, chunk_delay_ms: int, recheck_ms: int,
             build_delay_ms: int, lease_seconds: int) -> dict[str, str]:
        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
            "SCOPEPACK_HOME": str(self.home),
            "SCOPEPACK_REGISTRY_BASE": self.base,
            "SCOPEPACK_BUILDER_BASE": self.builder_base,
            "SCOPEPACK_REGISTRY_PORT": str(self.registry_port),
            "SCOPEPACK_BUILDER_PORT": str(self.builder_port),
            "SCOPEPACK_NODE_A_PORT": str(self.node_a_port),
            "SCOPEPACK_NODE_B_PORT": str(self.node_b_port),
            "SCOPEPACK_SERVICE_TOKEN": SERVICE,
            "SCOPEPACK_ADMIN_TOKEN": ADMIN,
            "SCOPEPACK_PSEUDONYM_SECRET": PEPPER,
            "SCOPEPACK_DATASET_ROWS": "1200",
            "SCOPEPACK_EDGE_CHUNK_BYTES": str(chunk_bytes),
            "SCOPEPACK_EDGE_CHUNK_DELAY_MS": str(chunk_delay_ms),
            "SCOPEPACK_EDGE_RECHECK_MS": str(recheck_ms),
            "SCOPEPACK_BUILDER_BUILD_DELAY_MS": str(build_delay_ms),
            "SCOPEPACK_BUILDER_LEASE_SECONDS": str(lease_seconds),
            "SCOPEPACK_GRANT_TTL_SECONDS": str(self.grant_ttl),
        })
        return env

    def spawn(self, name: str, args: list[str]) -> None:
        log_path = self.home / f"{name}.log"
        handle = log_path.open("wb")
        self.handles.append(handle)
        self.logs[name] = log_path
        self.procs[name] = subprocess.Popen(
            [sys.executable, *args], cwd=ROOT, env=self.env,
            stdout=handle, stderr=subprocess.STDOUT,
        )

    def start(self, *, edges: bool = True, builder: bool = True) -> "Cluster":
        self.spawn("registry", ["-m", "scopepack.registry.app"])
        self._wait(self.base + "/healthz", "registry")
        if builder:
            self.spawn("builder", ["-m", "scopepack.builder.app"])
            self._wait(self.builder_base + "/healthz", "builder")
        if edges:
            self.spawn("edge-a", ["-m", "scopepack.consumer.edge", "--node-id", "node-a"])
            self.spawn("edge-b", ["-m", "scopepack.consumer.edge", "--node-id", "node-b"])
            self._wait(self.node_a + "/healthz", "edge-a")
            self._wait(self.node_b + "/healthz", "edge-b")
        return self

    def _wait(self, url: str, name: str, timeout: float = 25.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status, _ = http("GET", url, timeout=1.0)
                if status == 200:
                    return
            except (urllib.error.URLError, OSError):
                pass
            if name in self.procs and self.procs[name].poll() is not None:
                raise RuntimeError(f"{name} exited early:\n{self.log(name)[-4000:]}")
            time.sleep(0.1)
        raise RuntimeError(f"timed out waiting for {name}:\n{self.log(name)[-4000:]}")

    def kill(self, name: str) -> None:
        proc = self.procs.get(name)
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    def log(self, name: str) -> str:
        path = self.logs.get(name)
        if not path or not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def token(self, consumer: str) -> str:
        tokens = json.loads((self.home / "consumer-tokens.json").read_text())
        return tokens[consumer]

    def stop(self) -> None:
        for name, proc in self.procs.items():
            if proc.poll() is None:
                proc.terminate()
        deadline = time.time() + 8
        for name, proc in self.procs.items():
            try:
                proc.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                proc.kill()
        for handle in self.handles:
            handle.close()
        shutil.rmtree(self.home, ignore_errors=True)

    # --------------------------------------------------------------- helpers
    def admin(self, method: str, path: str, body: Any | None = None) -> tuple[int, Any]:
        return http(method, self.base + path, body, {"X-Admin-Token": ADMIN})

    def consumer(self, token: str, method: str, path: str, body: Any | None = None,
                 extra: dict[str, str] | None = None) -> tuple[int, Any]:
        headers = {"Authorization": f"Bearer {token}"}
        headers.update(extra or {})
        return http(method, self.base + path, body, headers)

    def purpose(self, code: str) -> dict[str, Any]:
        status, payload = self.admin("GET", f"/api/v1/admin/purposes/{code}")
        assert status == 200, payload
        return payload

    def overview(self) -> dict[str, Any]:
        status, payload = self.admin("GET", "/api/v1/admin/overview")
        assert status == 200, payload
        return payload

    def renew(self, consumer: str, key: str) -> dict[str, Any]:
        status, payload = self.consumer(self.token(consumer), "POST", "/consumer/v1/renew",
                                        {"renewal_key": key, "note": "test renewal"})
        assert status == 200, payload
        return payload

    def apply_policy(self, code: str, fields: list[str], note: str = "test") -> dict[str, Any]:
        status, payload = self.admin("POST", f"/api/v1/admin/purposes/{code}/policy",
                                     {"fields": fields, "note": note})
        assert status == 200, payload
        return payload

    def wait_package(self, package_key: str, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for purpose in self.overview()["purposes"]:
                for pkg in purpose["packages"]:
                    if pkg["package_key"] == package_key and pkg["status"] in ("ready", "failed", "retired"):
                        return pkg
            time.sleep(0.1)
        raise RuntimeError(f"package {package_key} did not settle:\n{self.log('builder')[-3000:]}")

    def grant(self, consumer: str, node: str = "node-a", key: str | None = None) -> tuple[int, Any]:
        return self.consumer(self.token(consumer), "POST", "/consumer/v1/grants",
                             {"node_id": node, "issue_key": key or f"issue-{time.time_ns()}"})

    def download(self, consumer: str, grant_id: str, node_base: str,
                 extra_headers: dict[str, str] | None = None,
                 max_bytes: int | None = None,
                 range_start: int | None = None) -> tuple[int, bytes, dict[str, str]]:
        request = urllib.request.Request(
            node_base + "/downloads",
            data=json.dumps({"grant_id": grant_id}).encode(), method="POST")
        request.add_header("Authorization", f"Bearer {self.token(consumer)}")
        request.add_header("Content-Type", "application/json")
        if range_start is not None:
            request.add_header("Range", f"bytes={range_start}-")
        for key, value in (extra_headers or {}).items():
            request.add_header(key, value)
        with urllib.request.urlopen(request, timeout=30) as response:
            body = b""
            while True:
                if max_bytes is not None and len(body) >= max_bytes:
                    break
                chunk = response.read(min(2048, max_bytes - len(body)) if max_bytes else 2048)
                if not chunk:
                    break
                body += chunk
            headers = {k.lower(): v for k, v in response.getheaders()}
            return response.status, body, headers

    def edge_cache(self, node_base: str) -> dict[str, Any]:
        status, payload = http("GET", node_base + "/admin/cache", headers={"X-Service-Token": SERVICE})
        assert status == 200, payload
        return payload


class ClusterCase(unittest.TestCase):
    cluster_kwargs: dict[str, Any] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.cluster = Cluster(**cls.cluster_kwargs).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.cluster.stop()

    def warm_purpose(self, consumer: str, purpose: str) -> dict[str, Any]:
        payload = self.cluster.renew(consumer, f"warm-{consumer}")
        pkg = payload["package"]
        if pkg["status"] != "ready":
            pkg = self.cluster.wait_package(pkg["package_key"])
        self.assertEqual(pkg["status"], "ready", pkg)
        return pkg
