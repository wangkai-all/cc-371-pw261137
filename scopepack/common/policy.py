"""Field allow-lists, purpose policies and deterministic package rendering.

Design choice
-------------
Packages are generated per purpose from the purpose's *contract* at build time.
The artifact therefore never contains a disallowed column — not even encrypted
or hashed — so a download node's disk cache cannot leak a field that a later
policy renewal removes.  Read-time trimming was rejected because the shared
delivery tier would have to hold the union of all fields, turning every edge
cache into a full-sensitivity copy, and a slow download would still have the
whole body in flight.

Historical retention is separate: packages and audit rows are never deleted,
but their status/reachability is recomputed against the purpose's *current*
policy on every lease and every data chunk.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .util import canonical_json, sha256_text

# Deterministic fictional dataset.  "Sensitive" columns exist in the source so
# that a naive copy would leak them; purpose policies decide which may ship.
SOURCE_FIELDS: tuple[tuple[str, str, str, str], ...] = (
    ("trip_id", "identifier", "low", "Stable trip identifier"),
    ("driver_ref", "identifier", "medium", "Pseudo driver reference"),
    ("vehicle_ref", "identifier", "medium", "Pseudo vehicle reference"),
    ("city", "location", "medium", "City of trip start"),
    ("started_at", "timestamp", "low", "Trip start time (UTC)"),
    ("distance_km", "metric", "low", "Distance in kilometres"),
    ("duration_min", "metric", "low", "Duration in minutes"),
    ("fare_amount", "metric", "high", "Passenger fare"),
    ("tip_amount", "metric", "high", "Tip amount"),
    ("payment_method", "attribute", "medium", "Payment instrument family"),
    ("rating", "attribute", "medium", "Passenger rating"),
    ("driver_name", "personal", "high", "Driver full name"),
    ("driver_phone", "personal", "high", "Driver mobile number"),
    ("passenger_name", "personal", "high", "Passenger full name"),
    ("pickup_address", "location", "high", "Street-level pickup"),
    ("dropoff_address", "location", "high", "Street-level dropoff"),
    ("gps_trace", "telemetry", "high", "Simplified GPS polyline"),
    ("vehicle_vin", "identifier", "high", "Vehicle identification number"),
)

FIELD_ORDER: tuple[str, ...] = tuple(f[0] for f in SOURCE_FIELDS)

FIELD_CATALOG: dict[str, dict[str, str]] = {
    name: {"category": category, "sensitivity": sensitivity, "description": description}
    for name, category, sensitivity, description in SOURCE_FIELDS
}


@dataclass(frozen=True)
class Purpose:
    code: str
    name: str
    description: str
    allowed: tuple[str, ...]


# Initial fictional purposes.  Renewals tighten these; the demo never widens.
DEFAULT_PURPOSES: tuple[Purpose, ...] = (
    Purpose(
        code="finance",
        name="Finance settlement",
        description="Monthly settlement and cost reconciliation by the finance team.",
        allowed=(
            "trip_id", "city", "started_at", "distance_km", "duration_min",
            "fare_amount", "tip_amount", "payment_method", "vehicle_ref",
        ),
    ),
    Purpose(
        code="safety",
        name="Safety investigation",
        description="Investigate reported incidents and audit driver conduct.",
        allowed=(
            "trip_id", "driver_ref", "vehicle_ref", "city", "started_at",
            "duration_min", "driver_name", "driver_phone", "gps_trace",
        ),
    ),
    Purpose(
        code="analytics",
        name="City analytics",
        description="Aggregated mobility and demand research without personal data.",
        allowed=("trip_id", "city", "started_at", "distance_km", "duration_min", "rating"),
    ),
)


def validate_field_subset(fields: Iterable[str]) -> list[str]:
    unknown = sorted({f for f in fields if f not in FIELD_CATALOG})
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(unknown)}")
    return sorted(set(fields), key=FIELD_ORDER.index)


def policy_decision(allowed: Sequence[str], field: str) -> tuple[bool, str]:
    if field not in FIELD_CATALOG:
        return False, "field is not part of the source catalog"
    if field in allowed:
        return True, "allowed by purpose contract"
    category = FIELD_CATALOG[field]["category"]
    sensitivity = FIELD_CATALOG[field]["sensitivity"]
    if category == "personal":
        return False, f"personal data ({sensitivity} sensitivity) is excluded by purpose"
    if category == "telemetry":
        return False, "granular telemetry is excluded by purpose"
    if category == "location":
        return False, "street-level location is excluded by purpose"
    return False, f"field not granted to this purpose ({sensitivity} sensitivity)"


def build_manifest(
    *,
    package_key: str,
    purpose_code: str,
    policy_version: int,
    policy_hash: str,
    dataset_version: str,
    dataset_sha256: str,
    row_count: int,
    allowed_fields: Sequence[str],
    excluded_fields: Mapping[str, str],
    pseudonymised_fields: Sequence[str],
) -> dict[str, Any]:
    return {
        "format": "scopepack/1",
        "package_key": package_key,
        "purpose": purpose_code,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "dataset": {"version": dataset_version, "sha256_upper_bound": dataset_sha256},
        "row_count": row_count,
        "fields": [
            {
                "name": field,
                "category": FIELD_CATALOG[field]["category"],
                "sensitivity": FIELD_CATALOG[field]["sensitivity"],
                "pseudonymised": field in pseudonymised_fields,
            }
            for field in allowed_fields
        ],
        "excluded": [
            {"field": field, "reason": reason}
            for field, reason in sorted(excluded_fields.items(), key=lambda kv: FIELD_ORDER.index(kv[0]))
        ],
        "delivery": {
            "mode": "per-purpose-package",
            "trim_at_read": False,
            "recheck": "authorize every chunk against current policy",
        },
    }


def render_row(record: Mapping[str, Any], allowed: Sequence[str]) -> dict[str, Any]:
    return {field: record[field] for field in allowed if field in record}


def render_ndjson(records: Iterable[Mapping[str, Any]], allowed: Sequence[str]) -> bytes:
    lines = [canonical_json(render_row(rec, allowed)) for rec in records]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def manifest_fingerprint(manifest: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(manifest))
