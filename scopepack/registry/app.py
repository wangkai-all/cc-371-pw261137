"""Scopepack registry / subscription service.

Port 7101.  Owns the control-plane database, policy versions, contracts,
packages' authorization facts, grants, download events and acknowledgements.
It never serves bulk data: bytes go through the download edges.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
from pathlib import Path
from typing import Any, Iterable, Sequence

from scopepack.common.config import Settings, load_settings, node_base
from scopepack.common.db import connect, initialize, transaction
from scopepack.common.http import ApiError, JsonResponse, Request, Service, http_json
from scopepack.common.policy import (
    FIELD_CATALOG,
    FIELD_ORDER,
    build_manifest,
    manifest_fingerprint,
    policy_decision,
    validate_field_subset,
)
from scopepack.common.seed import seed_everything
from scopepack.common.util import (
    canonical_json,
    hmac_hex,
    is_past,
    iso_after,
    new_id,
    now_iso,
    parse_iso,
    safe_equal,
    sha256_text,
    token_hash,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("scopepack.registry")

WEB_DIR = Path(__file__).resolve().parents[1] / "web"


class Registry:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.conn = initialize(settings.db_path)
        self.build_signing_key = hmac_hex(settings.pseudonym_secret, "package-manifest-signing")
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ auth
    def require_admin(self, req: Request) -> None:
        supplied = req.header("X-Admin-Token") or (req.bearer() or "")
        if not supplied or not safe_equal(supplied, self.settings.admin_token):
            raise ApiError(401, "admin_auth_required", "a valid admin token is required")

    def require_service(self, req: Request) -> None:
        supplied = req.header("X-Service-Token") or (req.bearer() or "")
        if not supplied or not safe_equal(supplied, self.settings.service_token):
            raise ApiError(401, "service_auth_required", "a valid service token is required")

    def subscription_from_token(self, token: str | None) -> dict[str, Any]:
        if not token:
            raise ApiError(401, "consumer_auth_required", "a subscription bearer token is required")
        row = self.conn.execute(
            "SELECT * FROM subscriptions WHERE token_hash = ?", (token_hash(token),)
        ).fetchone()
        if row is None:
            raise ApiError(401, "invalid_consumer_token", "subscription token is not recognized")
        if row["status"] != "active":
            raise ApiError(403, "subscription_suspended", "subscription is suspended")
        return dict(row)

    def require_consumer(self, req: Request) -> dict[str, Any]:
        return self.subscription_from_token(req.bearer())

    # ------------------------------------------------------------------ audit
    def audit(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: Any,
        detail: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> None:
        self.conn.execute(
            """INSERT INTO audit_events(at, actor, action, entity_type, entity_id, request_id, detail_json)
               VALUES(?,?,?,?,?,?,?)""",
            (now_iso(), actor, action, entity_type, str(entity_id), request_id,
             canonical_json(detail or {})),
        )

    # --------------------------------------------------------------- lookups
    def purpose_by_code(self, code: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM purposes WHERE code = ?", (code,)).fetchone()
        if row is None:
            raise ApiError(404, "purpose_not_found", f"purpose '{code}' does not exist")
        return dict(row)

    def active_policy(self, purpose_id: int) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM policy_versions WHERE purpose_id = ? AND status = 'active'",
            (purpose_id,),
        ).fetchone()
        if row is None:
            raise ApiError(500, "missing_policy", "purpose has no active policy version")
        return dict(row)

    def policy_rules(self, policy_version_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT field, allowed, reason FROM policy_rules
               WHERE policy_version_id = ? ORDER BY rowid""",
            (policy_version_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def allowed_fields(self, policy_version_id: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT field FROM policy_rules WHERE policy_version_id = ? AND allowed = 1",
            (policy_version_id,),
        ).fetchall()
        fields = [r["field"] for r in rows]
        return sorted(fields, key=FIELD_ORDER.index)

    def active_dataset(self) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM dataset_versions ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            raise ApiError(500, "missing_dataset", "no dataset version registered")
        return dict(row)

    # ------------------------------------------------------ packages / jobs
    def _package_for(self, purpose_id: int, policy_id: int, dataset_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM packages WHERE purpose_id=? AND policy_version_id=? AND dataset_version_id=?",
            (purpose_id, policy_id, dataset_id),
        ).fetchone()
        return dict(row) if row else None

    def ensure_package(self, purpose_id: int, policy_id: int, dataset_id: int, actor: str) -> dict[str, Any]:
        """Create a package + queued build job exactly once for the tuple."""
        existing = self._package_for(purpose_id, policy_id, dataset_id)
        if existing:
            if existing["status"] == "failed":
                return self.retry_package(existing["id"], actor)
            return existing
        purpose = self.conn.execute("SELECT code FROM purposes WHERE id=?", (purpose_id,)).fetchone()
        policy = self.conn.execute("SELECT version FROM policy_versions WHERE id=?", (policy_id,)).fetchone()
        dataset = self.conn.execute("SELECT version FROM dataset_versions WHERE id=?", (dataset_id,)).fetchone()
        fields = self.allowed_fields(policy_id)
        fields_hash = sha256_text(canonical_json(fields))
        package_key = f"pkg-{purpose['code']}-p{policy['version']}-{dataset['version']}"
        if self.conn.execute("SELECT 1 FROM packages WHERE package_key=?", (package_key,)).fetchone():
            package_key += "-" + new_id("r")[-6:]
        timestamp = now_iso()
        with transaction(self.conn):
            cur = self.conn.execute(
                """INSERT INTO packages(package_key, purpose_id, policy_version_id, dataset_version_id,
                       status, allowed_fields, fields_hash, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (package_key, purpose_id, policy_id, dataset_id, "pending",
                 canonical_json(fields), fields_hash, timestamp),
            )
            package_id = cur.lastrowid
            self.conn.execute(
                """INSERT INTO build_jobs(package_id, status, created_at, updated_at)
                   VALUES(?, 'queued', ?, ?)""",
                (package_id, timestamp, timestamp),
            )
            self.audit(actor, "package.queued", "package", package_id,
                       {"package_key": package_key, "fields": fields})
        return dict(self.conn.execute("SELECT * FROM packages WHERE id=?", (package_id,)).fetchone())

    def retry_package(self, package_id: int, actor: str, *, requeue_ready: bool = False) -> dict[str, Any]:
        """Re-queue a failed or explicitly rebuilt package under the same key.

        Rebuilding a ready package flips it to ``pending`` in place: the old
        artifact stays on disk until the new one lands, but edges stop serving
        it (their purge loop sees a non-downloadable state) and grants are
        rejected until the rebuild completes.  This is a maintenance action,
        not something a routine renewal does.
        """
        package = self.conn.execute("SELECT * FROM packages WHERE id=?", (package_id,)).fetchone()
        if package is None:
            raise ApiError(404, "package_not_found", "package does not exist")
        if package["status"] == "ready" and not requeue_ready:
            return dict(package)
        if package["status"] == "building":
            raise ApiError(409, "package_building", "package is already being built")
        with transaction(self.conn):
            self.conn.execute(
                """UPDATE packages SET status='pending', failure_reason=NULL, blocked_at=NULL,
                       blocked_reason=NULL WHERE id=?""",
                (package_id,),
            )
            job = self.conn.execute("SELECT * FROM build_jobs WHERE package_id=?", (package_id,)).fetchone()
            if job:
                self.conn.execute(
                    """UPDATE build_jobs SET status='queued', lease_owner=NULL, lease_token=NULL,
                           lease_expires_at=NULL, last_error=NULL, updated_at=? WHERE package_id=?""",
                    (now_iso(), package_id),
                )
            else:
                self.conn.execute(
                    "INSERT INTO build_jobs(package_id, status, created_at, updated_at) VALUES(?, 'queued', ?, ?)",
                    (package_id, now_iso(), now_iso()),
                )
            self.audit(actor, "package.rebuild_requested", "package", package_id, {})
        return dict(self.conn.execute("SELECT * FROM packages WHERE id=?", (package_id,)).fetchone())

    def retire_other_packages(self, purpose_id: int, keep_package_id: int, reason: str) -> list[dict[str, Any]]:
        """Retire artifacts built under superseded policies.

        The package for the *active* policy is never touched here, including a
        pending or building one: a late completion of an older artifact must
        not knock out the replacement.
        """
        active = self.active_policy(purpose_id)
        rows = self.conn.execute(
            """SELECT * FROM packages WHERE purpose_id=? AND id<>?
               AND policy_version_id <> ?
               AND status IN ('ready','building','pending','blocked','failed')""",
            (purpose_id, keep_package_id, active["id"]),
        ).fetchall()
        retired = []
        for row in rows:
            self.conn.execute(
                """UPDATE packages SET status='retired', retired_at=?, retention_note=?
                   WHERE id=?""",
                (now_iso(), reason, row["id"]),
            )
            self.revoke_grants_for_package(row["id"], "package_retired", "retention: artifact kept for audit only")
            retired.append(dict(row))
        return retired

    # -------------------------------------------------------------- contracts
    def create_contract(self, subscription: dict[str, Any], policy: dict[str, Any],
                        package: dict[str, Any], dataset: dict[str, Any],
                        renewal_key: str | None, note: str) -> dict[str, Any]:
        purpose_id = subscription["purpose_id"]
        current = self.conn.execute(
            "SELECT * FROM contracts WHERE subscription_id=? AND status='active' ORDER BY version DESC LIMIT 1",
            (subscription["id"],),
        ).fetchone()
        policy_allowed = self.allowed_fields(policy["id"])
        previous_allowed: list[str] = json.loads(current["allowed_fields"]) if current else policy_allowed
        # Renewals may only narrow: intersect with the previous contract.  New
        # subscriptions start from the full purpose policy.
        allowed = [f for f in policy_allowed if f in previous_allowed or current is None]
        allowed = sorted(set(allowed), key=FIELD_ORDER.index)
        if not allowed:
            raise ApiError(409, "empty_contract", "renewal would leave no allowed fields")
        previous_reasons: dict[str, str] = json.loads(current["disallowed_fields"]) if current else {}
        disallowed: dict[str, str] = {}
        for field in FIELD_ORDER:
            if field in allowed:
                continue
            if field in previous_reasons and field not in policy_allowed:
                disallowed[field] = "removed from the purpose policy at renewal: " + previous_reasons[field]
            else:
                ok, reason = policy_decision(policy_allowed, field)
                disallowed[field] = reason
        removed = sorted(set(previous_allowed) - set(allowed), key=FIELD_ORDER.index)
        change_kind = "initial"
        if current is not None:
            if current["policy_version_id"] == policy["id"] and set(previous_allowed) == set(allowed):
                return dict(current)
            change_kind = "narrowed" if removed else "policy_renewal"
        version = (current["version"] + 1) if current else 1
        fields_hash = sha256_text(canonical_json(allowed))
        timestamp = now_iso()
        with transaction(self.conn):
            if current is not None:
                self.conn.execute(
                    "UPDATE contracts SET status='superseded', superseded_at=? WHERE id=?",
                    (timestamp, current["id"]),
                )
            cur = self.conn.execute(
                """INSERT INTO contracts(subscription_id, version, purpose_id, package_id,
                       policy_version_id, allowed_fields, disallowed_fields, fields_hash,
                       policy_hash, status, change_kind, note, effective_at, renewal_key)
                   VALUES(?,?,?,?,?,?,?,?,?, 'active', ?,?,?,?)""",
                (subscription["id"], version, purpose_id, package["id"], policy["id"],
                 canonical_json(allowed), canonical_json(disallowed), fields_hash,
                 policy["policy_hash"], change_kind, note, timestamp, renewal_key),
            )
            contract_id = cur.lastrowid
            if current is not None:
                self.revoke_grants_for_contract(current["id"], "contract_superseded",
                                                f"superseded by contract v{version}")
            self.audit("consumer:" + subscription["consumer_id"], "contract.created", "contract",
                       contract_id, {"version": version, "change_kind": change_kind,
                                     "allowed_fields": allowed, "removed_fields": removed,
                                     "policy_version": policy["version"]})
        return dict(self.conn.execute("SELECT * FROM contracts WHERE id=?", (contract_id,)).fetchone())

    # ----------------------------------------------------------------- grants
    def revoke_grants_for_contract(self, contract_id: int, reason: str, detail: str) -> int:
        rows = self.conn.execute(
            "SELECT grant_id FROM grants WHERE contract_id=? AND revoked_at IS NULL", (contract_id,)
        ).fetchall()
        if not rows:
            return 0
        timestamp = now_iso()
        self.conn.execute(
            "UPDATE grants SET revoked_at=?, revoked_reason=? WHERE contract_id=? AND revoked_at IS NULL",
            (timestamp, reason, contract_id),
        )
        for row in rows:
            self.audit("registry", "grant.revoked", "grant", row["grant_id"],
                       {"reason": reason, "detail": detail})
        return len(rows)

    def revoke_grants_for_package(self, package_id: int, reason: str, detail: str) -> int:
        rows = self.conn.execute(
            "SELECT grant_id FROM grants WHERE package_id=? AND revoked_at IS NULL", (package_id,)
        ).fetchall()
        if not rows:
            return 0
        timestamp = now_iso()
        self.conn.execute(
            "UPDATE grants SET revoked_at=?, revoked_reason=? WHERE package_id=? AND revoked_at IS NULL",
            (timestamp, reason, package_id),
        )
        for row in rows:
            self.audit("registry", "grant.revoked", "grant", row["grant_id"],
                       {"reason": reason, "detail": detail})
        return len(rows)

    def grant_status(self, grant: dict[str, Any]) -> tuple[bool, str, str, dict[str, Any] | None]:
        """Return (allowed, code, reason, package) against *current* facts."""
        subscription = self.conn.execute(
            "SELECT * FROM subscriptions WHERE id=?", (grant["subscription_id"],)
        ).fetchone()
        if subscription is None or subscription["status"] != "active":
            return False, "subscription_inactive", "subscription is suspended or missing", None
        if grant["revoked_at"]:
            return False, "grant_revoked", f"grant revoked: {grant['revoked_reason']}", None
        if is_past(grant["expires_at"]):
            return False, "grant_expired", "grant lifetime elapsed; request a new grant", None
        contract = self.conn.execute("SELECT * FROM contracts WHERE id=?", (grant["contract_id"],)).fetchone()
        if contract is None or contract["status"] != "active":
            return False, "contract_inactive", "contract is no longer active", None
        package = self.conn.execute("SELECT * FROM packages WHERE id=?", (grant["package_id"],)).fetchone()
        if package is None:
            return False, "package_missing", "package record is missing", None
        if package["status"] == "retired":
            return False, "package_retired", "package was retired after a policy change; retained for audit only", dict(package)
        if package["status"] != "ready":
            return False, "package_not_ready", f"package is {package['status']}", dict(package)
        purpose = self.conn.execute("SELECT * FROM purposes WHERE id=?", (package["purpose_id"],)).fetchone()
        if purpose is None or purpose["status"] != "active":
            return False, "purpose_inactive", "purpose is no longer active", dict(package)
        current_policy = self.active_policy(package["purpose_id"])
        if current_policy["id"] != package["policy_version_id"]:
            return (False, "policy_narrowed",
                    "current purpose policy differs from the package's policy; renew the contract",
                    dict(package))
        if contract["policy_version_id"] != current_policy["id"]:
            return False, "renewal_required", "contract predates the current policy; renew to continue", dict(package)
        current_allowed = set(self.allowed_fields(current_policy["id"]))
        contract_fields = set(json.loads(contract["allowed_fields"]))
        if not contract_fields.issubset(current_allowed):
            removed = sorted(contract_fields - current_allowed, key=FIELD_ORDER.index)
            return (False, "policy_narrowed",
                    "fields no longer allowed: " + ", ".join(removed), dict(package))
        return True, "allowed", "package is authorized by the current policy", dict(package)

    def find_renewal_request(self, subscription_id: int, renewal_key: str) -> Any | None:
        row = self.conn.execute(
            """SELECT c.* FROM renewal_requests r JOIN contracts c ON c.id=r.contract_id
               WHERE r.subscription_id=? AND r.renewal_key=?""",
            (subscription_id, renewal_key),
        ).fetchone()
        return row

    # ------------------------------------------------------------- serialize
    def package_view(self, row: Any, *, detail: bool = False) -> dict[str, Any]:
        package = dict(row)
        manifest = json.loads(package["manifest_json"]) if package["manifest_json"] else None
        view = {
            "id": package["id"],
            "package_key": package["package_key"],
            "purpose_id": package["purpose_id"],
            "purpose_code": self.conn.execute(
                "SELECT code FROM purposes WHERE id=?", (package["purpose_id"],)
            ).fetchone()["code"],
            "policy_version_id": package["policy_version_id"],
            "policy_version": self.conn.execute(
                "SELECT version FROM policy_versions WHERE id=?", (package["policy_version_id"],)
            ).fetchone()["version"],
            "dataset_version_id": package["dataset_version_id"],
            "status": package["status"],
            "allowed_fields": json.loads(package["allowed_fields"]),
            "fields_hash": package["fields_hash"],
            "content_sha256": package["content_sha256"],
            "size_bytes": package["size_bytes"],
            "row_count": package["row_count"],
            "created_at": package["created_at"],
            "ready_at": package["ready_at"],
            "retired_at": package["retired_at"],
            "retention_note": package["retention_note"],
            "blocked_reason": package["blocked_reason"],
            "failure_reason": package["failure_reason"],
            "build_attempts": package["build_attempts"],
            "manifest": manifest,
            "signature": package["signature"],
            "downloadable": package["status"] == "ready",
        }
        if detail:
            view["authorization_basis"] = self.package_basis(package)
        return view

    def package_basis(self, package: dict[str, Any]) -> dict[str, Any]:
        policy = self.conn.execute("SELECT * FROM policy_versions WHERE id=?",
                                   (package["policy_version_id"],)).fetchone()
        rules = self.policy_rules(package["policy_version_id"])
        contracts = self.conn.execute(
            """SELECT c.id, c.version, c.status, c.change_kind, c.effective_at, c.allowed_fields,
                      s.consumer_id, s.name
               FROM contracts c JOIN subscriptions s ON s.id=c.subscription_id
               WHERE c.package_id=? ORDER BY c.id""",
            (package["id"],),
        ).fetchall()
        grants = self.conn.execute(
            "SELECT * FROM grants WHERE package_id=? ORDER BY id DESC LIMIT 20", (package["id"],)
        ).fetchall()
        acks = self.conn.execute(
            "SELECT * FROM acks WHERE package_id=? ORDER BY id DESC LIMIT 20", (package["id"],)
        ).fetchall()
        events = self.conn.execute(
            """SELECT e.* FROM download_events e JOIN grants g ON g.grant_id=e.grant_id
               WHERE g.package_id=? ORDER BY e.id DESC LIMIT 30""",
            (package["id"],),
        ).fetchall()
        purpose = self.conn.execute("SELECT * FROM purposes WHERE id=?", (package["purpose_id"],)).fetchone()
        return {
            "purpose": dict(purpose),
            "policy": {
                "id": policy["id"], "version": policy["version"], "status": policy["status"],
                "policy_hash": policy["policy_hash"], "created_at": policy["created_at"],
                "created_by": policy["created_by"], "note": policy["note"],
            },
            "rules": rules,
            "contracts": [dict(r) | {"allowed_fields": json.loads(r["allowed_fields"])} for r in contracts],
            "grants": [dict(r) for r in grants],
            "acks": [dict(r) for r in acks],
            "download_events": [dict(r) for r in events],
            "current_policy": self.active_policy(package["purpose_id"]),
        }

    def contract_view(self, row: Any) -> dict[str, Any]:
        contract = dict(row)
        package = self.conn.execute("SELECT * FROM packages WHERE id=?", (contract["package_id"],)).fetchone()
        renewal_needed = False
        try:
            current = self.active_policy(contract["purpose_id"])
            renewal_needed = current["id"] != contract["policy_version_id"]
        except ApiError:
            pass
        return {
            "id": contract["id"],
            "version": contract["version"],
            "status": contract["status"],
            "change_kind": contract["change_kind"],
            "effective_at": contract["effective_at"],
            "superseded_at": contract["superseded_at"],
            "allowed_fields": json.loads(contract["allowed_fields"]),
            "disallowed_fields": json.loads(contract["disallowed_fields"]),
            "fields_hash": contract["fields_hash"],
            "policy_version_id": contract["policy_version_id"],
            "package_id": contract["package_id"],
            "package_key": package["package_key"] if package else None,
            "package_status": package["status"] if package else None,
            "package_sha256": package["content_sha256"] if package else None,
            "renewal_required": renewal_needed,
            "note": contract["note"],
        }

    # --------------------------------------------------------------- preview
    def preview_policy(self, purpose: dict[str, Any], requested: Sequence[str], note: str) -> dict[str, Any]:
        current_policy = self.active_policy(purpose["id"])
        current_fields = self.allowed_fields(current_policy["id"])
        try:
            wanted = validate_field_subset(requested)
        except ValueError as exc:
            raise ApiError(422, "invalid_fields", str(exc)) from exc
        added = [f for f in wanted if f not in current_fields]
        if added:
            raise ApiError(
                409, "widening_not_allowed",
                "renewal policies can only remove fields; widening requires a new purpose",
                {"widened_fields": added},
            )
        removed = [f for f in current_fields if f not in wanted]
        dataset = self.active_dataset()
        package = self._package_for(purpose["id"], current_policy["id"], dataset["id"])
        subscriptions = self.conn.execute(
            "SELECT * FROM subscriptions WHERE purpose_id=? ORDER BY id", (purpose["id"],)
        ).fetchall()
        active_contracts = self.conn.execute(
            """SELECT c.*, s.consumer_id, s.name FROM contracts c
               JOIN subscriptions s ON s.id=c.subscription_id
               WHERE c.purpose_id=? AND c.status='active' ORDER BY c.id""",
            (purpose["id"],),
        ).fetchall()
        exposed = []
        for contract in active_contracts:
            fields = json.loads(contract["allowed_fields"])
            hit = [f for f in removed if f in fields]
            if hit:
                exposed.append({
                    "contract_id": contract["id"], "consumer_id": contract["consumer_id"],
                    "name": contract["name"], "version": contract["version"],
                    "fields": hit,
                })
        old_packages = self.conn.execute(
            "SELECT * FROM packages WHERE purpose_id=? AND status IN ('ready','building','pending')",
            (purpose["id"],),
        ).fetchall()
        grants = self.conn.execute(
            """SELECT COUNT(*) AS n FROM grants g JOIN packages p ON p.id=g.package_id
               WHERE p.purpose_id=? AND g.revoked_at IS NULL""",
            (purpose["id"],),
        ).fetchone()["n"]
        sessions = self.node_sessions()
        size_estimate = self.estimate_size(wanted, dataset)
        return {
            "purpose": {"code": purpose["code"], "name": purpose["name"]},
            "current_policy": {"id": current_policy["id"], "version": current_policy["version"]},
            "proposed": {
                "fields": wanted,
                "would_create_policy_version": current_policy["version"] + 1,
                "note": note,
            },
            "removed_fields": [
                {"field": f, "category": FIELD_CATALOG[f]["category"],
                 "sensitivity": FIELD_CATALOG[f]["sensitivity"],
                 "reason": policy_decision(wanted, f)[1]} for f in removed
            ],
            "unchanged_fields": [f for f in current_fields if f in wanted],
            "affected": {
                "subscriptions": len(subscriptions),
                "active_contracts": len(active_contracts),
                "contracts_losing_fields": exposed,
                "packages_retired": len(old_packages),
                "grants_to_revoke": grants,
                "active_download_sessions": sessions,
            },
            "new_package": {
                "estimated_rows": dataset["row_count"],
                "estimated_size_bytes": size_estimate,
                "current_package": self.package_view(package) if package else None,
                "action": "queue rebuild under new policy; old artifacts retained but not downloadable",
            },
            "renewal_required": len(exposed) > 0,
        }

    def estimate_size(self, fields: Sequence[str], dataset: dict[str, Any]) -> int:
        try:
            sample = 0
            total = 0
            with self.settings.source_path.open("rb") as handle:
                for line in handle:
                    if sample >= 200:
                        break
                    record = json.loads(line)
                    total += len(canonical_json({f: record[f] for f in fields}).encode())
                    sample += 1
            if sample == 0:
                return 0
            return int(total / sample * dataset["row_count"])
        except OSError:
            return 0

    # ----------------------------------------------------------------- nodes
    def node_health(self) -> list[dict[str, Any]]:
        nodes = []
        for node_id, name, base in (
            ("node-a", "Download edge A", node_base("node-a", self.settings)),
            ("node-b", "Download edge B", node_base("node-b", self.settings)),
        ):
            entry = {"node_id": node_id, "name": name, "base_url": base, "healthy": False, "detail": ""}
            try:
                status, payload = http_json("GET", base + "/healthz", timeout=0.8)
                if status == 200 and isinstance(payload, dict):
                    entry.update(payload)
                    entry["healthy"] = True
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                entry["detail"] = str(exc)
            nodes.append(entry)
        return nodes

    def node_sessions(self) -> int:
        total = 0
        for node_id in ("node-a", "node-b"):
            try:
                status, payload = http_json(
                    "GET", node_base(node_id, self.settings) + "/admin/sessions",
                    headers={"X-Service-Token": self.settings.service_token}, timeout=0.6,
                )
                if status == 200 and isinstance(payload, dict):
                    total += int(payload.get("active", 0))
            except (urllib.error.URLError, OSError, TimeoutError):
                continue
        return total

    def overview(self) -> dict[str, Any]:
        purposes = []
        for purpose in self.conn.execute("SELECT * FROM purposes ORDER BY id"):
            policy = self.active_policy(purpose["id"])
            packages = self.conn.execute(
                "SELECT * FROM packages WHERE purpose_id=? ORDER BY id DESC", (purpose["id"],)
            ).fetchall()
            subs = self.conn.execute(
                "SELECT COUNT(*) AS n FROM subscriptions WHERE purpose_id=?", (purpose["id"],)
            ).fetchone()["n"]
            purposes.append({
                "code": purpose["code"], "name": purpose["name"], "description": purpose["description"],
                "status": purpose["status"],
                "policy": {"id": policy["id"], "version": policy["version"],
                           "hash": policy["policy_hash"], "created_at": policy["created_at"]},
                "allowed_fields": self.allowed_fields(policy["id"]),
                "subscriptions": subs,
                "packages": [self.package_view(p) for p in packages],
            })
        audit = self.conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 25").fetchall()
        acks = self.conn.execute(
            """SELECT classification, COUNT(*) AS n FROM acks GROUP BY classification"""
        ).fetchall()
        return {
            "service": "scopepack-registry",
            "now": now_iso(),
            "dataset": self.active_dataset(),
            "field_catalog": [
                {"field": f, "category": FIELD_CATALOG[f]["category"],
                 "sensitivity": FIELD_CATALOG[f]["sensitivity"],
                 "description": FIELD_CATALOG[f]["description"]} for f in FIELD_ORDER
            ],
            "purposes": purposes,
            "nodes": self.node_health(),
            "ack_classification": {r["classification"]: r["n"] for r in acks},
            "audit": [dict(r) | {"detail": json.loads(r["detail_json"])} for r in audit],
        }


REGISTRY: Registry


def register_routes(service: Service) -> None:
    # ------------------------------------------------------------------ basic
    @service.get("/healthz")
    def health(_: Request):
        return {"status": "ok", "service": "registry", "now": now_iso()}

    @service.get("/")
    def index(req: Request):
        return serve_static(req.path)

    @service.get("/static/(?P<name>[A-Za-z0-9._-]+)")
    def static(req: Request):
        return serve_static("/static/" + req.param("name"))

    # ------------------------------------------------------------ admin API
    @service.get(r"/api/v1/admin/overview")
    def admin_overview(req: Request):
        REGISTRY.require_admin(req)
        return REGISTRY.overview()

    @service.get(r"/api/v1/admin/purposes")
    def admin_purposes(req: Request):
        REGISTRY.require_admin(req)
        rows = []
        for purpose in REGISTRY.conn.execute("SELECT * FROM purposes ORDER BY id"):
            policy = REGISTRY.active_policy(purpose["id"])
            rows.append(dict(purpose) | {
                "active_policy": {"id": policy["id"], "version": policy["version"],
                                  "policy_hash": policy["policy_hash"]},
                "allowed_fields": REGISTRY.allowed_fields(policy["id"]),
            })
        return {"purposes": rows, "field_catalog": [
            {"field": f, "category": FIELD_CATALOG[f]["category"],
             "sensitivity": FIELD_CATALOG[f]["sensitivity"]} for f in FIELD_ORDER
        ]}

    @service.get(r"/api/v1/admin/purposes/(?P<code>[a-z0-9_-]+)")
    def admin_purpose(req: Request):
        REGISTRY.require_admin(req)
        purpose = REGISTRY.purpose_by_code(req.param("code"))
        policy = REGISTRY.active_policy(purpose["id"])
        packages = REGISTRY.conn.execute(
            "SELECT * FROM packages WHERE purpose_id=? ORDER BY id DESC", (purpose["id"],)
        ).fetchall()
        contracts = REGISTRY.conn.execute(
            """SELECT c.*, s.consumer_id, s.name FROM contracts c
               JOIN subscriptions s ON s.id=c.subscription_id
               WHERE c.purpose_id=? ORDER BY c.id DESC""",
            (purpose["id"],),
        ).fetchall()
        subscriptions = REGISTRY.conn.execute(
            "SELECT * FROM subscriptions WHERE purpose_id=? ORDER BY id", (purpose["id"],)
        ).fetchall()
        policies = REGISTRY.conn.execute(
            "SELECT * FROM policy_versions WHERE purpose_id=? ORDER BY version DESC", (purpose["id"],)
        ).fetchall()
        return {
            "purpose": dict(purpose),
            "policy": {"id": policy["id"], "version": policy["version"],
                       "policy_hash": policy["policy_hash"], "created_at": policy["created_at"],
                       "created_by": policy["created_by"], "note": policy["note"]},
            "rules": REGISTRY.policy_rules(policy["id"]),
            "allowed_fields": REGISTRY.allowed_fields(policy["id"]),
            "history": [dict(p) for p in policies],
            "packages": [REGISTRY.package_view(p) for p in packages],
            "subscriptions": [dict(s) for s in subscriptions],
            "contracts": [REGISTRY.contract_view(c) for c in contracts],
            "field_catalog": [
                {"field": f, "category": FIELD_CATALOG[f]["category"],
                 "sensitivity": FIELD_CATALOG[f]["sensitivity"],
                 "description": FIELD_CATALOG[f]["description"]} for f in FIELD_ORDER
            ],
        }

    @service.post(r"/api/v1/admin/purposes/(?P<code>[a-z0-9_-]+)/preview")
    def admin_preview(req: Request):
        REGISTRY.require_admin(req)
        purpose = REGISTRY.purpose_by_code(req.param("code"))
        body = req.body()
        fields = body.get("fields")
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
            raise ApiError(422, "invalid_fields", "body.fields must be a list of field names")
        return REGISTRY.preview_policy(purpose, fields, str(body.get("note") or ""))

    @service.post(r"/api/v1/admin/purposes/(?P<code>[a-z0-9_-]+)/policy")
    def admin_apply_policy(req: Request):
        REGISTRY.require_admin(req)
        purpose = REGISTRY.purpose_by_code(req.param("code"))
        body = req.body()
        fields = body.get("fields")
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
            raise ApiError(422, "invalid_fields", "body.fields must be a list of field names")
        note = str(body.get("note") or "")
        preview = REGISTRY.preview_policy(purpose, fields, note)
        removed = [item["field"] for item in preview["removed_fields"]]
        if not removed and not body.get("force"):
            raise ApiError(409, "no_change", "proposed field set equals the current policy")
        dataset = REGISTRY.active_dataset()
        timestamp = now_iso()
        with transaction(REGISTRY.conn):
            rules = []
            for field in FIELD_ORDER:
                allowed, reason = policy_decision(fields, field)
                rules.append((field, 1 if allowed else 0, reason))
            policy_hash = sha256_text(canonical_json(sorted(rules)))
            new_version = REGISTRY.active_policy(purpose["id"])["version"] + 1
            REGISTRY.conn.execute(
                "UPDATE policy_versions SET status='retired' WHERE purpose_id=? AND status='active'",
                (purpose["id"],),
            )
            cur = REGISTRY.conn.execute(
                """INSERT INTO policy_versions(purpose_id, version, status, policy_hash, created_at, created_by, note)
                   VALUES(?,?, 'active', ?,?,?,?)""",
                (purpose["id"], new_version, policy_hash, timestamp,
                 body.get("actor") or "web-admin", note),
            )
            policy_id = cur.lastrowid
            REGISTRY.conn.executemany(
                "INSERT INTO policy_rules(policy_version_id, field, allowed, reason) VALUES(?,?,?,?)",
                [(policy_id, f, a, r) for f, a, r in rules],
            )
            package = REGISTRY.ensure_package(purpose["id"], policy_id, dataset["id"], "web-admin")
            # Freeze older artifacts immediately: they must not appear usable
            # while the replacement builds.  They flip to 'retired' (audit-only)
            # once the new package is ready.
            older = REGISTRY.conn.execute(
                """SELECT id FROM packages WHERE purpose_id=? AND id<>?
                   AND status IN ('ready','pending','building')""",
                (purpose["id"], package["id"]),
            ).fetchall()
            revoked = 0
            for row in older:
                REGISTRY.conn.execute(
                    """UPDATE packages SET status='blocked', blocked_at=?, blocked_reason=?
                       WHERE id=?""",
                    (timestamp,
                     f"policy v{new_version} no longer matches this artifact; replacement queued",
                     row["id"]),
                )
                revoked += REGISTRY.revoke_grants_for_package(
                    row["id"], "policy_narrowed",
                    f"purpose policy v{new_version} retired this artifact")
            for contract in REGISTRY.conn.execute(
                    "SELECT id FROM contracts WHERE purpose_id=? AND status='active'",
                    (purpose["id"],)).fetchall():
                revoked += REGISTRY.revoke_grants_for_contract(
                    contract["id"], "policy_narrowed",
                    f"purpose policy v{new_version} removed fields at {timestamp}")
            REGISTRY.audit("web-admin", "policy.applied", "purpose", purpose["id"], {
                "new_policy_version": new_version,
                "removed_fields": removed,
                "package_id": package["id"],
                "package_key": package["package_key"],
                "revoked_grants": revoked,
            }, req.request_id)
        return {
            "status": "policy_applied_build_queued",
            "policy_version": new_version,
            "policy_id": policy_id,
            "removed_fields": removed,
            "revoked_grants": revoked,
            "package": REGISTRY.package_view(
                REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?", (package["id"],)).fetchone()),
            "preview": preview,
        }

    @service.post(r"/api/v1/admin/purposes/(?P<code>[a-z0-9_-]+)/rebuild")
    def admin_rebuild(req: Request):
        REGISTRY.require_admin(req)
        purpose = REGISTRY.purpose_by_code(req.param("code"))
        policy = REGISTRY.active_policy(purpose["id"])
        dataset = REGISTRY.active_dataset()
        package = REGISTRY.ensure_package(purpose["id"], policy["id"], dataset["id"], "web-admin")
        force = bool(req.body().get("force"))
        if package["status"] == "ready" and not force:
            return {"status": "already_ready", "package": REGISTRY.package_view(
                REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?", (package["id"],)).fetchone())}
        if package["status"] in ("failed", "ready"):
            package = REGISTRY.retry_package(package["id"], "web-admin", requeue_ready=force)
        REGISTRY.audit("web-admin", "package.rebuild_requested", "purpose", purpose["id"],
                       {"package_id": package["id"]}, req.request_id)
        return {"status": "queued", "package": REGISTRY.package_view(
            REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?", (package["id"],)).fetchone())}

    @service.get(r"/api/v1/admin/packages/(?P<pid>[0-9]+)")
    def admin_package(req: Request):
        REGISTRY.require_admin(req)
        row = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?", (int(req.param("pid")),)).fetchone()
        if row is None:
            raise ApiError(404, "package_not_found", "package does not exist")
        return {"package": REGISTRY.package_view(row, detail=True)}

    @service.get(r"/api/v1/admin/audit")
    def admin_audit(req: Request):
        REGISTRY.require_admin(req)
        limit = min(500, max(1, int(req.q("limit", "100") or "100")))
        entity = req.q("entity_id")
        action = req.q("action")
        sql = "SELECT * FROM audit_events WHERE 1=1"
        args: list[Any] = []
        if entity:
            sql += " AND entity_id=?"
            args.append(entity)
        if action:
            sql += " AND action LIKE ?"
            args.append(action + "%")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = REGISTRY.conn.execute(sql, args).fetchall()
        return {"audit": [dict(r) | {"detail": json.loads(r["detail_json"])} for r in rows]}

    @service.get(r"/api/v1/admin/nodes")
    def admin_nodes(req: Request):
        REGISTRY.require_admin(req)
        return {"nodes": REGISTRY.node_health()}

    # ---------------------------------------------------------- consumer API
    def deduplicated_renewal(subscription: dict[str, Any], prior: Any) -> dict[str, Any]:
        """Answer a retried renewal without creating or reviving a contract.

        If the retried key refers to a contract that has since been superseded,
        return the *current* contract instead.  Replaying an old key must never
        make an outdated field set active again.
        """
        active = REGISTRY.conn.execute(
            "SELECT * FROM contracts WHERE subscription_id=? AND status='active' "
            "ORDER BY version DESC LIMIT 1", (subscription["id"],),
        ).fetchone()
        contract = active if active is not None else prior
        package = REGISTRY.conn.execute(
            "SELECT * FROM packages WHERE id=?", (contract["package_id"],)).fetchone()
        return {
            "status": "renewed",
            "deduplicated": True,
            "replayed_contract_version": prior["version"],
            "contract": REGISTRY.contract_view(contract),
            "package": REGISTRY.package_view(package),
            "renewal_hint": (
                "retry of an already processed renewal"
                if active is not None and active["id"] == prior["id"]
                else "retried key superseded by a newer contract; the current contract is returned"
            ),
        }

    @service.post(r"/consumer/v1/renew")
    def consumer_renew(req: Request):
        subscription = REGISTRY.require_consumer(req)
        body = req.body()
        renewal_key = body.get("renewal_key")
        if renewal_key is not None and not isinstance(renewal_key, str):
            raise ApiError(422, "invalid_renewal_key", "renewal_key must be a string")
        if renewal_key:
            dedupe = REGISTRY.find_renewal_request(subscription["id"], renewal_key)
            if dedupe is not None:
                return deduplicated_renewal(subscription, dedupe)
        purpose = REGISTRY.conn.execute(
            "SELECT * FROM purposes WHERE id=?", (subscription["purpose_id"],)).fetchone()
        if purpose is None or purpose["status"] != "active":
            raise ApiError(409, "purpose_inactive", "purpose is not active")
        dataset = REGISTRY.active_dataset()
        with REGISTRY._lock, transaction(REGISTRY.conn):
            policy = REGISTRY.active_policy(subscription["purpose_id"])
            dataset = REGISTRY.active_dataset()
            # Re-check dedupe inside the write lock.
            if renewal_key:
                dedupe = REGISTRY.find_renewal_request(subscription["id"], renewal_key)
                if dedupe is not None:
                    return deduplicated_renewal(subscription, dedupe)
            package = REGISTRY.ensure_package(subscription["purpose_id"], policy["id"], dataset["id"],
                                               "consumer:" + subscription["consumer_id"])
            contract = REGISTRY.create_contract(
                subscription, policy, package, dataset, renewal_key,
                str(body.get("note") or ""))
            if renewal_key:
                REGISTRY.conn.execute(
                    """INSERT OR IGNORE INTO renewal_requests(subscription_id, renewal_key,
                           contract_id, created_at) VALUES(?,?,?,?)""",
                    (subscription["id"], renewal_key, contract["id"], now_iso()),
                )
            package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                            (contract["package_id"],)).fetchone()
            REGISTRY.audit("consumer:" + subscription["consumer_id"], "subscription.renewed",
                           "subscription", subscription["id"],
                           {"contract_version": contract["version"],
                            "package_status": package["status"]}, req.request_id)
        response_status = "ready" if package["status"] == "ready" else "building"
        return {
            "status": "renewed",
            "contract": REGISTRY.contract_view(contract),
            "package": REGISTRY.package_view(package),
            "download_available": package["status"] == "ready",
            "state": response_status,
            "nodes": [node_base("node-a", REGISTRY.settings), node_base("node-b", REGISTRY.settings)],
        }

    @service.get(r"/consumer/v1/contract")
    def consumer_contract(req: Request):
        subscription = REGISTRY.require_consumer(req)
        contract = REGISTRY.conn.execute(
            "SELECT * FROM contracts WHERE subscription_id=? AND status='active' ORDER BY version DESC LIMIT 1",
            (subscription["id"],),
        ).fetchone()
        if contract is None:
            raise ApiError(404, "no_contract", "subscription has no active contract; renew first")
        return {"contract": REGISTRY.contract_view(contract),
                "subscription": {"consumer_id": subscription["consumer_id"], "name": subscription["name"]}}

    @service.post(r"/consumer/v1/grants")
    def consumer_grant(req: Request):
        subscription = REGISTRY.require_consumer(req)
        body = req.body()
        node = body.get("node_id") or "node-a"
        if node not in ("node-a", "node-b"):
            raise ApiError(422, "invalid_node", "node_id must be node-a or node-b")
        contract = REGISTRY.conn.execute(
            "SELECT * FROM contracts WHERE subscription_id=? AND status='active' ORDER BY version DESC LIMIT 1",
            (subscription["id"],),
        ).fetchone()
        if contract is None:
            raise ApiError(409, "renewal_required", "no active contract; renew first")
        package = REGISTRY.conn.execute(
            "SELECT * FROM packages WHERE id=?", (contract["package_id"],)).fetchone()
        if package is None:
            raise ApiError(409, "package_missing", "contract package is missing")
        current = REGISTRY.active_policy(subscription["purpose_id"])
        if current["id"] != contract["policy_version_id"]:
            raise ApiError(409, "renewal_required",
                           "purpose policy changed; renew the subscription before downloading",
                           {"current_policy_version": current["version"]})
        if package["status"] != "ready":
            raise ApiError(409, "package_not_ready", f"package is {package['status']}",
                           {"package_key": package["package_key"]})
        allowed = set(json.loads(contract["allowed_fields"]))
        missing = sorted(allowed - set(REGISTRY.allowed_fields(current["id"])), key=FIELD_ORDER.index)
        if missing:
            raise ApiError(409, "policy_narrowed",
                           "contract contains fields the current policy forbids; renew first",
                           {"fields": missing})
        issue_key = body.get("issue_key")
        if issue_key:
            existing = REGISTRY.conn.execute(
                "SELECT * FROM grants WHERE subscription_id=? AND issue_key=?",
                (subscription["id"], str(issue_key)),
            ).fetchone()
            if existing is not None:
                if existing["revoked_at"]:
                    raise ApiError(409, "renewal_required",
                                   "the grant for this issue key was revoked "
                                   f"({existing['revoked_reason']}); renew before downloading")
                return grant_payload(existing, node, deduplicated=True)
        grant_id = new_id("grant")
        timestamp = now_iso()
        expires = iso_after(REGISTRY.settings.grant_ttl_seconds)
        with transaction(REGISTRY.conn):
            REGISTRY.conn.execute(
                """INSERT INTO grants(grant_id, package_id, contract_id, subscription_id, consumer_id,
                       issued_at, expires_at, node_id, issue_key)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (grant_id, package["id"], contract["id"], subscription["id"],
                 subscription["consumer_id"], timestamp, expires, node, issue_key),
            )
            REGISTRY.audit("consumer:" + subscription["consumer_id"], "grant.issued", "grant", grant_id, {
                "package_key": package["package_key"], "node_id": node, "expires_at": expires,
            }, req.request_id)
        row = REGISTRY.conn.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
        return grant_payload(row, node, deduplicated=False)

    def grant_payload(grant: Any, node: str, deduplicated: bool) -> dict[str, Any]:
        package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                        (grant["package_id"],)).fetchone()
        return {
            "status": "granted",
            "deduplicated": deduplicated,
            "grant": dict(grant),
            "package": REGISTRY.package_view(package),
            "edge": {"node_id": node, "base_url": node_base(node, REGISTRY.settings)},
            "instruction": "POST edge /downloads with this bearer token and grant_id",
        }

    # ------------------------------------------------------------- edge API
    @service.post(r"/edge/v1/authorize")
    def edge_authorize(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        grant_id = body.get("grant_id")
        if not isinstance(grant_id, str):
            raise ApiError(422, "invalid_grant", "grant_id is required")
        token = body.get("consumer_token")
        if token:
            subscription = REGISTRY.subscription_from_token(token)
        else:
            subscription = None
        grant = REGISTRY.conn.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
        if grant is None:
            return {"decision": "deny", "code": "grant_not_found",
                    "reason": "grant does not exist", "checked_at": now_iso()}
        if subscription is not None and subscription["id"] != grant["subscription_id"]:
            return {"decision": "deny", "code": "grant_subscription_mismatch",
                    "reason": "token belongs to another subscription", "checked_at": now_iso()}
        allowed, code, reason, package = REGISTRY.grant_status(dict(grant))
        REGISTRY.conn.execute(
            """INSERT INTO download_events(grant_id, node_id, event, bytes, at, detail)
               VALUES(?,?,?,?,?,?)""",
            (grant_id, str(body.get("node_id") or grant["node_id"]),
             "authorize_ok" if allowed else "authorize_denied", 0, now_iso(), code),
        )
        if not allowed:
            REGISTRY.audit("edge:" + str(body.get("node_id") or grant["node_id"]),
                           "download.denied", "grant", grant_id, {"code": code, "reason": reason})
            return {"decision": "deny", "code": code, "reason": reason, "checked_at": now_iso(),
                    "retain_artifact": code in ("policy_narrowed", "package_retired", "renewal_required")}
        contract = REGISTRY.conn.execute("SELECT * FROM contracts WHERE id=?",
                                         (grant["contract_id"],)).fetchone()
        policy = REGISTRY.conn.execute("SELECT * FROM policy_versions WHERE id=?",
                                       (package["policy_version_id"],)).fetchone()
        return {
            "decision": "allow",
            "code": "allowed",
            "reason": reason,
            "checked_at": now_iso(),
            "grant_id": grant_id,
            "expires_at": grant["expires_at"],
            "node_id": body.get("node_id") or grant["node_id"],
            "consumer": {"consumer_id": grant["consumer_id"]},
            "contract": {
                "id": contract["id"], "version": contract["version"],
                "allowed_fields": json.loads(contract["allowed_fields"]),
                "fields_hash": contract["fields_hash"], "status": contract["status"],
            },
            "purpose": {"id": package["purpose_id"],
                        "code": REGISTRY.conn.execute("SELECT code FROM purposes WHERE id=?",
                                                     (package["purpose_id"],)).fetchone()["code"]},
            "package": {
                "id": package["id"], "package_key": package["package_key"],
                "status": package["status"], "content_sha256": package["content_sha256"],
                "size_bytes": package["size_bytes"], "row_count": package["row_count"],
                "allowed_fields": json.loads(package["allowed_fields"]),
                "manifest": json.loads(package["manifest_json"]),
                "signature": package["signature"],
            },
            "policy": {"id": policy["id"], "version": policy["version"],
                       "policy_hash": policy["policy_hash"]},
        }

    @service.get(r"/edge/v1/packages/(?P<key>[A-Za-z0-9._-]+)/state")
    def edge_package_state(req: Request):
        REGISTRY.require_service(req)
        package = REGISTRY.conn.execute(
            "SELECT * FROM packages WHERE package_key=?", (req.param("key"),)).fetchone()
        if package is None:
            return {"package_key": req.param("key"), "downloadable": False, "code": "package_missing"}
        current = REGISTRY.active_policy(package["purpose_id"])
        downloadable = package["status"] == "ready" and current["id"] == package["policy_version_id"]
        reason = "ok" if downloadable else (
            "package_retired" if package["status"] == "retired" else
            "policy_narrowed" if current["id"] != package["policy_version_id"] else
            f"package_{package['status']}")
        return {
            "package_key": package["package_key"], "package_id": package["id"],
            "status": package["status"], "downloadable": downloadable, "code": reason,
            "current_policy_version": current["version"],
            "package_policy_version": REGISTRY.conn.execute(
                "SELECT version FROM policy_versions WHERE id=?", (package["policy_version_id"],)
            ).fetchone()["version"],
            "retention_note": package["retention_note"], "checked_at": now_iso(),
        }

    @service.post(r"/edge/v1/events")
    def edge_event(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        grant_id = str(body.get("grant_id") or "")
        event = str(body.get("event") or "")
        if not grant_id or not event:
            raise ApiError(422, "invalid_event", "grant_id and event are required")
        REGISTRY.conn.execute(
            """INSERT INTO download_events(grant_id, node_id, event, bytes, at, detail)
               VALUES(?,?,?,?,?,?)""",
            (grant_id, str(body.get("node_id") or ""), event, int(body.get("bytes") or 0),
             now_iso(), str(body.get("detail") or "")),
        )
        if event in ("stream_aborted", "cache_purged", "integrity_mismatch",
                     "prefetch_authorization_lost"):
            REGISTRY.audit("edge:" + str(body.get("node_id") or ""), "download." + event,
                           "grant", grant_id, {"detail": body.get("detail") or ""})
        return {"status": "recorded"}

    @service.post(r"/edge/v1/acks")
    def edge_ack(req: Request):
        """Consumer acknowledgements.

        The consumer authenticates with its subscription token; the edge and
        builder use the service token for their own calls.  Either credential
        is accepted, but a consumer may only acknowledge its own grant.
        """
        consumer = None
        if req.bearer():
            consumer = REGISTRY.subscription_from_token(req.bearer())
        else:
            REGISTRY.require_service(req)
        body = req.body()
        ack_id = body.get("ack_id")
        grant_id = body.get("grant_id")
        if not isinstance(ack_id, str) or not ack_id:
            raise ApiError(422, "invalid_ack", "ack_id is required")
        if not isinstance(grant_id, str) or not grant_id:
            raise ApiError(422, "invalid_ack", "grant_id is required")
        grant = REGISTRY.conn.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
        if grant is None:
            raise ApiError(404, "grant_not_found", "cannot acknowledge an unknown grant")
        if consumer is not None and consumer["id"] != grant["subscription_id"]:
            raise ApiError(403, "ack_forbidden", "a consumer may only acknowledge its own grants")
        existing = REGISTRY.conn.execute("SELECT * FROM acks WHERE ack_id=?", (ack_id,)).fetchone()
        if existing is not None:
            if existing["grant_id"] != grant_id:
                raise ApiError(409, "ack_id_conflict",
                               "ack_id is already used for a different grant")
            return {"status": "duplicate", "ack": dict(existing),
                    "classification": existing["classification"],
                    "counts_current": bool(existing["counts_current"])}
        package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                        (grant["package_id"],)).fetchone()
        contract = REGISTRY.conn.execute("SELECT * FROM contracts WHERE id=?",
                                         (grant["contract_id"],)).fetchone()
        reported_sha = body.get("sha256")
        if reported_sha is not None and package["content_sha256"] and reported_sha != package["content_sha256"]:
            classification = "integrity_mismatch"
            retained, counts_current = 0, 0
            detail = "reported digest does not match the package manifest; confirmation quarantined"
        elif package["status"] == "retired" or contract["status"] != "active":
            classification = "historic_retained"
            retained, counts_current = 1, 0
            detail = ("old-consumer confirmation for a superseded/retired package; retained for audit, "
                      "does not affect the current contract")
        elif grant["revoked_at"]:
            classification = "historic_retained"
            retained, counts_current = 1, 0
            detail = "confirmation arrived after grant revocation; retained for audit only"
        else:
            current = REGISTRY.active_policy(contract["purpose_id"])
            if current["id"] != contract["policy_version_id"] or package["status"] != "ready":
                classification = "historic_retained"
                retained, counts_current = 1, 0
                detail = "contract or package is no longer current"
            else:
                classification = "current"
                retained, counts_current = 1, 1
                detail = "confirmed against the active contract"
        with transaction(REGISTRY.conn):
            REGISTRY.conn.execute(
                """INSERT INTO acks(ack_id, grant_id, package_id, contract_id, subscription_id,
                       consumer_id, node_id, bytes, reported_sha256, classification, retained,
                       counts_current, received_at, detail)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ack_id, grant_id, package["id"], contract["id"], grant["subscription_id"],
                 grant["consumer_id"], str(body.get("node_id") or grant["node_id"]),
                 int(body.get("bytes") or 0), reported_sha, classification, retained,
                 counts_current, now_iso(), detail),
            )
            REGISTRY.audit("consumer:" + grant["consumer_id"], "download.acknowledged", "ack", ack_id,
                           {"grant_id": grant_id, "package_key": package["package_key"],
                            "classification": classification, "counts_current": bool(counts_current)})
        row = REGISTRY.conn.execute("SELECT * FROM acks WHERE ack_id=?", (ack_id,)).fetchone()
        return {"status": "recorded", "classification": classification,
                "counts_current": bool(counts_current), "retained": bool(retained),
                "detail": detail, "ack": dict(row)}

    @service.post(r"/edge/v1/nodes/heartbeat")
    def edge_heartbeat(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        node_id = str(body.get("node_id") or "")
        if not node_id:
            raise ApiError(422, "invalid_node", "node_id required")
        REGISTRY.conn.execute(
            """INSERT INTO nodes(node_id, name, base_url, last_seen, cache_bytes, cached_packages)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
                 last_seen=excluded.last_seen, cache_bytes=excluded.cache_bytes,
                 cached_packages=excluded.cached_packages, last_error=excluded.last_error""",
            (node_id, str(body.get("name") or node_id), str(body.get("base_url") or ""),
             now_iso(), int(body.get("cache_bytes") or 0), int(body.get("cached_packages") or 0)),
        )
        return {"status": "ok"}

    # -------------------------------------------------- builder-facing API
    @service.post(r"/builder/v1/jobs/lease")
    def builder_lease(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        owner = str(body.get("owner") or "builder")
        lease_seconds = min(300, max(2, int(body.get("lease_seconds") or 20)))
        now = now_iso()
        with transaction(REGISTRY.conn):
            # Never build an artifact whose policy is already gone.  Leased
            # jobs are left alone: that builder will archive its output itself.
            REGISTRY.conn.execute(
                """UPDATE build_jobs SET status='cancelled', updated_at=?
                   WHERE status='queued'
                     AND package_id IN (SELECT id FROM packages
                                        WHERE status IN ('retired','blocked'))""",
                (now,),
            )
            job = REGISTRY.conn.execute(
                """SELECT j.* FROM build_jobs j JOIN packages p ON p.id=j.package_id
                   WHERE (j.status='queued'
                          OR (j.status='leased' AND (j.lease_expires_at IS NULL OR j.lease_expires_at <= ?)))
                     AND p.status IN ('pending','building','blocked')
                   ORDER BY j.id LIMIT 1""",
                (now,),
            ).fetchone()
            if job is None:
                return {"job": None}
            token = new_id("lease")
            expires = iso_after(lease_seconds)
            REGISTRY.conn.execute(
                """UPDATE build_jobs SET status='leased', lease_owner=?, lease_token=?, lease_expires_at=?,
                       attempts=attempts+1, updated_at=? WHERE id=?""",
                (owner, token, expires, now, job["id"]),
            )
            REGISTRY.conn.execute(
                "UPDATE packages SET status='building', build_attempts=build_attempts+1 WHERE id=?",
                (job["package_id"],),
            )
            package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                            (job["package_id"],)).fetchone()
            dataset = REGISTRY.conn.execute("SELECT * FROM dataset_versions WHERE id=?",
                                            (package["dataset_version_id"],)).fetchone()
            policy = REGISTRY.conn.execute("SELECT * FROM policy_versions WHERE id=?",
                                           (package["policy_version_id"],)).fetchone()
            purpose = REGISTRY.conn.execute("SELECT * FROM purposes WHERE id=?",
                                            (package["purpose_id"],)).fetchone()
            rules = REGISTRY.policy_rules(policy["id"])
            REGISTRY.audit("builder:" + owner, "build.leased", "package", package["id"],
                           {"job_id": job["id"], "attempt": job["attempts"] + 1})
        return {
            "job": {
                "id": job["id"], "lease_token": token, "lease_expires_at": expires,
                "attempt": job["attempts"] + 1, "package_id": package["id"],
                "package_key": package["package_key"],
                "allowed_fields": json.loads(package["allowed_fields"]),
                "fields_hash": package["fields_hash"],
                "source_path": str(REGISTRY.settings.source_path),
                "dataset": dict(dataset),
                "purpose": {"code": purpose["code"], "name": purpose["name"]},
                "policy": {"id": policy["id"], "version": policy["version"],
                           "policy_hash": policy["policy_hash"]},
                "rules": rules,
                "artifacts_dir": str(REGISTRY.settings.artifacts_dir),
                "build_delay_ms": REGISTRY.settings.builder_build_delay_ms,
            }
        }

    @service.post(r"/builder/v1/jobs/(?P<jid>[0-9]+)/heartbeat")
    def builder_heartbeat(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        job = REGISTRY.conn.execute("SELECT * FROM build_jobs WHERE id=?", (int(req.param("jid")),)).fetchone()
        if job is None or job["status"] != "leased":
            raise ApiError(409, "job_not_leased", "job is not currently leased")
        if not safe_equal(str(body.get("lease_token") or ""), job["lease_token"] or ""):
            raise ApiError(409, "lease_conflict", "lease token does not match")
        lease_seconds = min(300, max(2, int(body.get("lease_seconds") or 20)))
        expires = iso_after(lease_seconds)
        REGISTRY.conn.execute(
            "UPDATE build_jobs SET lease_expires_at=?, updated_at=? WHERE id=?",
            (expires, now_iso(), job["id"]),
        )
        return {"status": "extended", "lease_expires_at": expires}

    @service.post(r"/builder/v1/jobs/(?P<jid>[0-9]+)/complete")
    def builder_complete(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        job = REGISTRY.conn.execute("SELECT * FROM build_jobs WHERE id=?", (int(req.param("jid")),)).fetchone()
        if job is None:
            raise ApiError(404, "job_not_found", "job does not exist")
        if job["status"] == "done":
            package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                            (job["package_id"],)).fetchone()
            if body.get("content_sha256") == package["content_sha256"]:
                return {"status": "already_complete", "package": REGISTRY.package_view(package)}
            raise ApiError(409, "job_already_complete", "job is already complete")
        if job["status"] != "leased":
            raise ApiError(409, "job_not_leased", f"job is {job['status']}")
        if not safe_equal(str(body.get("lease_token") or ""), job["lease_token"] or ""):
            raise ApiError(409, "lease_conflict", "lease token does not match")
        package = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?",
                                        (job["package_id"],)).fetchone()
        if package is None:
            raise ApiError(404, "package_not_found", "package does not exist")
        rules = REGISTRY.policy_rules(package["policy_version_id"])
        expected_allowed = [r["field"] for r in rules if r["allowed"] == 1]
        expected_allowed = sorted(expected_allowed, key=FIELD_ORDER.index)
        provided_fields = body.get("allowed_fields")
        if provided_fields != expected_allowed:
            raise ApiError(409, "manifest_field_mismatch",
                           "artifact fields do not match the package contract",
                           {"expected": expected_allowed, "provided": provided_fields})
        manifest = body.get("manifest")
        if not isinstance(manifest, dict):
            raise ApiError(422, "invalid_manifest", "manifest object is required")
        if manifest.get("package_key") != package["package_key"]:
            raise ApiError(409, "manifest_package_mismatch", "manifest package_key does not match")
        manifest_fields = [f.get("name") for f in manifest.get("fields", []) if isinstance(f, dict)]
        if manifest_fields != expected_allowed:
            raise ApiError(409, "manifest_field_mismatch", "manifest fields do not match contract")
        content_sha = str(body.get("content_sha256") or "")
        size_bytes = int(body.get("size_bytes") or 0)
        row_count = int(body.get("row_count") or 0)
        artifact_path = str(body.get("artifact_path") or "")
        if len(content_sha) != 64 or size_bytes <= 0 or row_count <= 0:
            raise ApiError(422, "invalid_artifact", "content_sha256, size_bytes and row_count are required")
        if not artifact_path.startswith(str(REGISTRY.settings.artifacts_dir)):
            raise ApiError(422, "invalid_artifact_path", "artifact must live under the artifacts directory")
        if not Path(artifact_path).exists():
            raise ApiError(422, "artifact_missing", "artifact file was not found at the reported path")
        package_key = package["package_key"]
        current_policy = REGISTRY.active_policy(package["purpose_id"])
        # Sign the content-addressed manifest so edges can verify what they cache.
        signature = hmac_hex(REGISTRY.build_signing_key,
                             content_sha + ":" + manifest_fingerprint(manifest))
        timestamp = now_iso()
        if current_policy["id"] != package["policy_version_id"]:
            # The policy moved on while this artifact was being built.  Keep
            # the bytes for audit but never publish them as downloadable, and
            # leave the replacement package and its job alone.
            artifact = Path(artifact_path)
            archive = artifact.with_name(
                f"{artifact.stem}.retired-{package['policy_version_id']}{artifact.suffix}")
            if artifact.exists():
                os.replace(artifact, archive)
            stale = REGISTRY.conn.execute(
                "SELECT version FROM policy_versions WHERE id=?",
                (package["policy_version_id"],)).fetchone()
            note = (f"Built under superseded policy v{stale['version']}; "
                    "retained for audit, not downloadable.")
            with REGISTRY._lock, transaction(REGISTRY.conn):
                REGISTRY.conn.execute(
                    """UPDATE packages SET status='retired', retired_at=?, retention_note=?,
                           content_sha256=?, size_bytes=?, row_count=?, artifact_path=?
                       WHERE id=?""",
                    (timestamp, note, content_sha, size_bytes, row_count,
                     str(archive), package["id"]),
                )
                REGISTRY.conn.execute(
                    "UPDATE build_jobs SET status='done', lease_expires_at=NULL, updated_at=? WHERE id=?",
                    (timestamp, job["id"]),
                )
                REGISTRY.audit("builder:" + str(job["lease_owner"]), "package.archived_superseded",
                               "package", package["id"],
                               {"package_key": package_key, "sha256": content_sha})
            archived = REGISTRY.conn.execute(
                "SELECT * FROM packages WHERE id=?", (package["id"],)).fetchone()
            return {"status": "archived_superseded", "package": REGISTRY.package_view(archived),
                    "retired_packages": []}
        with REGISTRY._lock, transaction(REGISTRY.conn):
            REGISTRY.conn.execute(
                """UPDATE packages SET status='ready', content_sha256=?, size_bytes=?, row_count=?,
                       artifact_path=?, manifest_json=?, signature=?, ready_at=?, failure_reason=NULL,
                       blocked_at=NULL, blocked_reason=NULL
                   WHERE id=?""",
                (content_sha, size_bytes, row_count, artifact_path, canonical_json(manifest),
                 signature, timestamp, package["id"]),
            )
            REGISTRY.conn.execute(
                "UPDATE build_jobs SET status='done', lease_expires_at=NULL, updated_at=? WHERE id=?",
                (timestamp, job["id"]),
            )
            retired = REGISTRY.retire_other_packages(
                package["purpose_id"], package["id"],
                f"Retained for audit after policy v{REGISTRY.conn.execute('SELECT version FROM policy_versions WHERE id=?', (package['policy_version_id'],)).fetchone()['version']} "
                f"replaced an earlier package on {timestamp}. Not downloadable.")
            REGISTRY.audit("builder:" + str(job["lease_owner"]), "package.ready", "package", package["id"],
                           {"package_key": package_key, "sha256": content_sha,
                            "size_bytes": size_bytes, "row_count": row_count,
                            "retired_packages": [r["package_key"] for r in retired]})
        ready = REGISTRY.conn.execute("SELECT * FROM packages WHERE id=?", (package["id"],)).fetchone()
        return {"status": "ready", "package": REGISTRY.package_view(ready),
                "retired_packages": [r["package_key"] for r in retired]}

    @service.post(r"/builder/v1/jobs/(?P<jid>[0-9]+)/fail")
    def builder_fail(req: Request):
        REGISTRY.require_service(req)
        body = req.body()
        job = REGISTRY.conn.execute("SELECT * FROM build_jobs WHERE id=?", (int(req.param("jid")),)).fetchone()
        if job is None:
            raise ApiError(404, "job_not_found", "job does not exist")
        if job["status"] == "leased" and not safe_equal(
                str(body.get("lease_token") or ""), job["lease_token"] or ""):
            raise ApiError(409, "lease_conflict", "lease token does not match")
        reason = str(body.get("reason") or "builder reported failure")[:500]
        with transaction(REGISTRY.conn):
            REGISTRY.conn.execute(
                """UPDATE build_jobs SET status='failed', last_error=?, lease_expires_at=NULL, updated_at=?
                   WHERE id=?""",
                (reason, now_iso(), job["id"]),
            )
            REGISTRY.conn.execute(
                "UPDATE packages SET status='failed', failure_reason=? WHERE id=?",
                (reason, job["package_id"]),
            )
            REGISTRY.audit("builder:" + str(job["lease_owner"]), "package.failed",
                           "package", job["package_id"], {"reason": reason})
        return {"status": "failed"}

    @service.get(r"/builder/v1/packages/(?P<key>[A-Za-z0-9._-]+)/artifact")
    def builder_artifact_meta(req: Request):
        REGISTRY.require_service(req)
        package = REGISTRY.conn.execute(
            "SELECT * FROM packages WHERE package_key=? AND status='ready'", (req.param("key"),)).fetchone()
        if package is None:
            raise ApiError(404, "artifact_not_found", "no ready artifact for that package")
        return {"package_key": package["package_key"], "content_sha256": package["content_sha256"],
                "size_bytes": package["size_bytes"], "artifact_url":
                f"{REGISTRY.settings.builder_base}/artifacts/{package['package_key']}",
                "manifest": json.loads(package["manifest_json"]),
                "signature": package["signature"]}


def serve_static(path: str) -> Any:
    from scopepack.common.http import StreamResponse
    if path == "/":
        file_path = WEB_DIR / "index.html"
        content_type = "text/html; charset=utf-8"
    else:
        name = path.removeprefix("/static/")
        if not name or "/" in name or ".." in name:
            raise ApiError(404, "not_found", "unknown static file")
        file_path = WEB_DIR / "static" / name
        content_type = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }.get(file_path.suffix, "application/octet-stream")
    if not file_path.exists():
        raise ApiError(404, "not_found", f"missing web asset {file_path.name}")
    data = file_path.read_bytes()
    return StreamResponse(200, content_type, len(data), [data])


def main() -> int:
    global REGISTRY
    settings = load_settings()
    settings.home.mkdir(parents=True, exist_ok=True)
    dataset = seed_everything(settings)
    REGISTRY = Registry(settings)
    service = Service("registry", settings.registry_port)
    service.guard = lambda: REGISTRY._lock
    register_routes(service)
    log.info("dataset %s rows=%s sha256=%s", dataset["version"], dataset["row_count"], dataset["sha256"][:12])
    service.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
