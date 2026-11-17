"""Runtime configuration shared by every Scopepack process.

All services are deliberately configured through environment variables so the
registry, builder and download nodes can live on different hosts.  In the demo
they run as four independent processes on localhost.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


@dataclass(frozen=True)
class Settings:
    home: Path
    db_path: Path
    source_path: Path
    artifacts_dir: Path
    edges_dir: Path
    registry_base: str
    builder_base: str
    registry_port: int
    builder_port: int
    node_a_port: int
    node_b_port: int
    service_token: str
    pseudonym_secret: str
    edge_recheck_ms: int
    edge_chunk_bytes: int
    edge_throttle_cap_ms: int
    builder_build_delay_ms: int
    builder_lease_seconds: int
    admin_token: str
    dataset_rows: int
    edge_chunk_delay_ms: int
    grant_ttl_seconds: int


def load_settings() -> Settings:
    home = _path("SCOPEPACK_HOME", REPO_ROOT / "var")
    return Settings(
        home=home,
        db_path=_path("SCOPEPACK_DB", home / "registry.sqlite3"),
        source_path=_path("SCOPEPACK_SOURCE", home / "source" / "trips.jsonl"),
        artifacts_dir=_path("SCOPEPACK_ARTIFACTS", home / "artifacts"),
        edges_dir=_path("SCOPEPACK_EDGES", home / "edges"),
        registry_base=os.environ.get("SCOPEPACK_REGISTRY_BASE", "http://127.0.0.1:7101").rstrip("/"),
        builder_base=os.environ.get("SCOPEPACK_BUILDER_BASE", "http://127.0.0.1:7102").rstrip("/"),
        registry_port=int(os.environ.get("SCOPEPACK_REGISTRY_PORT", "7101")),
        builder_port=int(os.environ.get("SCOPEPACK_BUILDER_PORT", "7102")),
        node_a_port=int(os.environ.get("SCOPEPACK_NODE_A_PORT", "7111")),
        node_b_port=int(os.environ.get("SCOPEPACK_NODE_B_PORT", "7112")),
        service_token=os.environ.get("SCOPEPACK_SERVICE_TOKEN", "dev-service-token-change-me"),
        pseudonym_secret=os.environ.get(
            "SCOPEPACK_PSEUDONYM_SECRET", "fictional-demo-pepper-do-not-use-in-production"
        ),
        edge_recheck_ms=max(50, int(os.environ.get("SCOPEPACK_EDGE_RECHECK_MS", "350"))),
        edge_chunk_bytes=max(512, int(os.environ.get("SCOPEPACK_EDGE_CHUNK_BYTES", "4096"))),
        edge_throttle_cap_ms=max(0, int(os.environ.get("SCOPEPACK_EDGE_THROTTLE_CAP_MS", "250"))),
        builder_build_delay_ms=max(0, int(os.environ.get("SCOPEPACK_BUILDER_BUILD_DELAY_MS", "0"))),
        builder_lease_seconds=max(2, int(os.environ.get("SCOPEPACK_BUILDER_LEASE_SECONDS", "20"))),
        admin_token=os.environ.get("SCOPEPACK_ADMIN_TOKEN", "dev-admin-token-change-me"),
        dataset_rows=max(40, int(os.environ.get("SCOPEPACK_DATASET_ROWS", "5000"))),
        edge_chunk_delay_ms=max(0, int(os.environ.get("SCOPEPACK_EDGE_CHUNK_DELAY_MS", "0"))),
        grant_ttl_seconds=max(3, int(os.environ.get("SCOPEPACK_GRANT_TTL_SECONDS", "120"))),
    )


def node_base(node_id: str, settings: Settings) -> str:
    port = settings.node_a_port if node_id == "node-a" else settings.node_b_port
    return f"http://127.0.0.1:{port}"
