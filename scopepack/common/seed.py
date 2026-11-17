"""Deterministic fictional source data and initial registry state.

Everything here is invented: names are made-up, phone numbers are in the
reserved 555-01xx range, addresses are fictional streets, and identifiers are
derived from a hash.  Regenerating with the same row count yields byte-identical
data so package content hashes are reproducible.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any

from .config import Settings
from .db import connect, initialize, transaction
from .policy import (
    DEFAULT_PURPOSES,
    FIELD_CATALOG,
    FIELD_ORDER,
    build_manifest,
    manifest_fingerprint,
    policy_decision,
    validate_field_subset,
)
from .util import (
    atomic_write,
    canonical_json,
    new_token,
    now_iso,
    sha256_bytes,
    sha256_text,
    token_hash,
)

FIRST_NAMES = (
    "Avery", "Blair", "Casey", "Dana", "Ellis", "Finley", "Gale", "Harper",
    "Indigo", "Jules", "Kai", "Lane", "Marlow", "Noor", "Oakley", "Parker",
    "Quinn", "Reese", "Sasha", "Tatum", "Uma", "Vale", "Wren", "Yuki", "Zion",
)
LAST_NAMES = (
    "Arden", "Bellamy", "Calder", "Dove", "Ember", "Frost", "Grove", "Hollow",
    "Ives", "Juniper", "Kestrel", "Lark", "Moss", "North", "Orchard", "Pine",
    "Quarry", "Ridge", "Stone", "Thorn", "Umber", "Vale", "Willow", "Yarrow",
)
CITIES = ("Aurora Bay", "Bramble", "Cedar Falls", "Dune City", "Elm Harbor", "Ferrow")
STREETS = ("Lumen St", "Birch Ave", "Harbor Rd", "Quartz Way", "Meadow Ln", "Cobalt Dr")
PAYMENTS = ("card", "wallet", "corporate", "cash")
PURPOSE_SEEDS = {
    "finance": ("FinOps Monthly", "finance"),
    "safety": ("Safety Review Desk", "safety"),
    "analytics": ("City Mobility Lab", "analytics"),
}


def _pseudo(prefix: str, n: int, salt: str) -> str:
    return f"{prefix}_{hashlib.sha256(f'{salt}:{n}'.encode()).hexdigest()[:10]}"


def generate_dataset(rows: int) -> bytes:
    rng = random.Random(20261117)
    lines: list[str] = []
    for i in range(rows):
        driver = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"
        passenger = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"
        city = rng.choice(CITIES)
        trace = []
        lat = 47.5 + rng.random()
        lon = -122.3 + rng.random()
        for _ in range(6):
            lat += rng.uniform(-0.004, 0.004)
            lon += rng.uniform(-0.004, 0.004)
            trace.append([round(lat, 5), round(lon, 5)])
        record: dict[str, Any] = {
            "trip_id": _pseudo("trip", i, "trip"),
            "driver_ref": _pseudo("drv", i % max(1, rows // 7), "driver"),
            "vehicle_ref": _pseudo("veh", i % max(1, rows // 9), "vehicle"),
            "city": city,
            "started_at": f"2026-{1 + (i % 9):02d}-{1 + (i % 27):02d}T{i % 24:02d}:{(i * 7) % 60:02d}:00Z",
            "distance_km": round(rng.uniform(0.4, 42.0), 2),
            "duration_min": round(rng.uniform(2.0, 95.0), 1),
            "fare_amount": round(rng.uniform(3.0, 140.0), 2),
            "tip_amount": round(rng.uniform(0.0, 22.0), 2),
            "payment_method": rng.choice(PAYMENTS),
            "rating": round(rng.uniform(1.0, 5.0), 1),
            "driver_name": driver,
            "driver_phone": f"555-01{i % 100:02d}",
            "passenger_name": passenger,
            "pickup_address": f"{100 + i % 900} {rng.choice(STREETS)}, {city}",
            "dropoff_address": f"{100 + (i * 3) % 900} {rng.choice(STREETS)}, {city}",
            "gps_trace": trace,
            "vehicle_vin": f"FIC{i:010d}VIN{i % 10}",
        }
        lines.append(canonical_json(record))
    return ("\n".join(lines) + "\n").encode("utf-8")


def ensure_source(settings: Settings) -> dict[str, Any]:
    """Create the fictional source and always keep it on record as a version.

    We do not silently mutate the source: every observed byte sequence is
    registered as its own dataset version.  The demo generates exactly one.
    """
    conn = initialize(settings.db_path)
    try:
        if settings.source_path.exists():
            raw = settings.source_path.read_bytes()
        else:
            raw = generate_dataset(settings.dataset_rows)
            atomic_write(settings.source_path, raw, mode=0o640)
        digest = sha256_bytes(raw)
        row_count = raw.count(b"\n")
        existing = conn.execute(
            "SELECT * FROM dataset_versions WHERE sha256 = ?", (digest,)
        ).fetchone()
        if existing:
            return dict(existing)
        version = "ds-" + digest[:12]
        with transaction(conn):
            conn.execute(
                """INSERT INTO dataset_versions(version, sha256, size_bytes, row_count, created_at, notes)
                   VALUES(?,?,?,?,?,?)""",
                (version, digest, len(raw), row_count, now_iso(), "Deterministic fictional seed data"),
            )
            # First-time catalog and purposes are seeded alongside the first dataset.
            for field, info in FIELD_CATALOG.items():
                conn.execute(
                    "INSERT OR IGNORE INTO field_catalog(field, category, sensitivity, description) VALUES(?,?,?,?)",
                    (field, info["category"], info["sensitivity"], info["description"]),
                )
            if conn.execute("SELECT COUNT(*) FROM purposes").fetchone()[0] == 0:
                for purpose in DEFAULT_PURPOSES:
                    cur = conn.execute(
                        "INSERT INTO purposes(code, name, description, status, created_at) VALUES(?,?,?,?,?)",
                        (purpose.code, purpose.name, purpose.description, "active", now_iso()),
                    )
                    purpose_id = cur.lastrowid
                    rules = []
                    for field in FIELD_ORDER:
                        allowed, reason = policy_decision(purpose.allowed, field)
                        rules.append((field, 1 if allowed else 0, reason))
                    policy_hash = sha256_text(canonical_json(sorted(rules)))
                    cur = conn.execute(
                        """INSERT INTO policy_versions(purpose_id, version, status, policy_hash, created_at, created_by, note)
                           VALUES(?,?,?,?,?,?,?)""",
                        (purpose_id, 1, "active", policy_hash, now_iso(), "seed", "Initial baseline policy"),
                    )
                    policy_id = cur.lastrowid
                    conn.executemany(
                        "INSERT INTO policy_rules(policy_version_id, field, allowed, reason) VALUES(?,?,?,?)",
                        [(policy_id, field, allowed, reason) for field, allowed, reason in rules],
                    )
        return dict(conn.execute("SELECT * FROM dataset_versions WHERE sha256 = ?", (digest,)).fetchone())
    finally:
        conn.close()


def seed_consumers(settings: Settings) -> Path:
    """Create the two download consumers with tokens, idempotently."""
    conn = connect(settings.db_path)
    token_file = settings.home / "consumer-tokens.json"
    try:
        existing = {
            row["consumer_id"]: row["token_hint"]
            for row in conn.execute("SELECT consumer_id, token_hint FROM subscriptions")
        }
        if token_file.exists():
            tokens = json.loads(token_file.read_text(encoding="utf-8"))
        else:
            tokens = {}
        created = False
        with transaction(conn):
            for consumer_id, (name, purpose_code) in PURPOSE_SEEDS.items():
                if consumer_id in existing:
                    continue
                purpose = conn.execute("SELECT * FROM purposes WHERE code = ?", (purpose_code,)).fetchone()
                if purpose is None:
                    raise RuntimeError(f"missing seed purpose {purpose_code}")
                token = new_token()
                conn.execute(
                    """INSERT INTO subscriptions(consumer_id, name, purpose_id, status, token_hash, token_hint, created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (consumer_id, name, purpose["id"], "active", token_hash(token), token[:7] + "…" + token[-4:], now_iso()),
                )
                tokens[consumer_id] = token
                created = True
        if created or not token_file.exists():
            atomic_write(token_file, json.dumps(tokens, indent=2, sort_keys=True).encode(), mode=0o600)
        return token_file
    finally:
        conn.close()


def seed_everything(settings: Settings) -> dict[str, Any]:
    settings.home.mkdir(parents=True, exist_ok=True)
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    dataset = ensure_source(settings)
    seed_consumers(settings)
    return dataset
