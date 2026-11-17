"""Authorization, policy narrowing and package lifecycle tests."""
from __future__ import annotations

import json
import sqlite3
import time
import unittest

from tests.harness import ADMIN, SERVICE, Cluster, ClusterCase, http


class PolicyLifecycleTests(ClusterCase):
    def test_01_renewal_builds_scoped_package(self):
        cluster = self.cluster
        payload = cluster.renew("finance", "finance-1")
        package = payload["package"]
        self.assertEqual(package["purpose_code"], "finance")
        self.assertEqual(package["status"], "pending")
        ready = cluster.wait_package(package["package_key"])
        self.assertEqual(ready["status"], "ready")
        self.assertGreater(ready["row_count"], 0)

        finance_fields = set(cluster.purpose("finance")["allowed_fields"])
        self.assertEqual(set(ready["allowed_fields"]), finance_fields)
        self.assertEqual(ready["manifest"]["delivery"]["mode"], "per-purpose-package")
        self.assertFalse(ready["manifest"]["delivery"]["trim_at_read"])
        excluded = {item["field"] for item in ready["manifest"]["excluded"]}
        for forbidden in ("driver_name", "driver_phone", "passenger_name", "gps_trace",
                          "pickup_address", "dropoff_address", "vehicle_vin"):
            self.assertIn(forbidden, excluded)
            self.assertNotIn(forbidden, ready["allowed_fields"])

    def test_02_builder_artifact_contains_no_denied_column(self):
        cluster = self.cluster
        purpose = cluster.purpose("finance")
        package = purpose["packages"][0]
        status, _, headers = None, None, None
        grant_status, grant = cluster.grant("finance", key="artifact-inspect")
        self.assertEqual(grant_status, 200)
        code, body, _ = cluster.download("finance", grant["grant"]["grant_id"], cluster.node_a)
        self.assertEqual(code, 200)
        rows = [json.loads(line) for line in body.decode().splitlines() if line]
        self.assertEqual(len(rows), package["row_count"])
        for row in rows[:50]:
            self.assertEqual(set(row), set(package["allowed_fields"]))
            self.assertNotIn("driver_name", row)

    def test_03_renewal_cannot_widen(self):
        cluster = self.cluster
        status, payload = cluster.admin("POST", "/api/v1/admin/purposes/finance/preview", {
            "fields": list(cluster.purpose("finance")["allowed_fields"]) + ["driver_phone"],
            "note": "attempt widening",
        })
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["error"]["code"], "widening_not_allowed")
        self.assertIn("driver_phone", payload["error"]["details"]["widened_fields"])

        status, payload = cluster.consumer(cluster.token("finance"), "POST",
                                           "/consumer/v1/renew", {"renewal_key": "widen-1"})
        self.assertEqual(status, 200)
        # A contract cannot gain fields from the purpose policy either.
        status, payload = cluster.admin("POST", "/api/v1/admin/purposes/finance/policy", {
            "fields": list(cluster.purpose("finance")["allowed_fields"]) + ["passenger_name"],
        })
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "widening_not_allowed")

    def test_04_preview_reports_impact_without_mutating(self):
        cluster = self.cluster
        before = cluster.purpose("safety")
        fields = [f for f in before["allowed_fields"] if f not in ("driver_phone",)]
        status, preview = cluster.admin("POST", "/api/v1/admin/purposes/safety/preview", {
            "fields": fields, "note": "remove phone",
        })
        self.assertEqual(status, 200, preview)
        self.assertEqual([item["field"] for item in preview["removed_fields"]], ["driver_phone"])
        self.assertEqual(preview["affected"]["subscriptions"], 1)
        self.assertEqual(preview["proposed"]["would_create_policy_version"],
                         before["policy"]["version"] + 1)
        after = cluster.purpose("safety")
        self.assertEqual(after["policy"]["version"], before["policy"]["version"])
        self.assertEqual(after["allowed_fields"], before["allowed_fields"])

    def test_05_policy_narrowing_retires_old_package_and_revokes(self):
        cluster = self.cluster
        cluster.renew("safety", "safety-old-contract")
        old_pkg = cluster.wait_package(cluster.purpose("safety")["packages"][0]["package_key"])
        self.assertEqual(old_pkg["status"], "ready")
        status, grant = cluster.grant("safety", key="pre-narrow")
        self.assertEqual(status, 200, grant)
        grant_id = grant["grant"]["grant_id"]

        fields = [f for f in cluster.purpose("safety")["allowed_fields"] if f != "driver_phone"]
        result = cluster.apply_policy("safety", fields, "remove driver phone")
        self.assertIn("driver_phone", result["removed_fields"])
        self.assertGreaterEqual(result["revoked_grants"], 1)

        time.sleep(0.2)
        overview = cluster.overview()
        safety = [p for p in overview["purposes"] if p["code"] == "safety"][0]
        old_view = [p for p in safety["packages"] if p["package_key"] == old_pkg["package_key"]][0]
        self.assertIn(old_view["status"], ("blocked", "retired"))
        self.assertFalse(old_view["downloadable"])

        new_key = [p["package_key"] for p in safety["packages"]
                   if p["package_key"] != old_pkg["package_key"]][0]
        new_pkg = cluster.wait_package(new_key)
        self.assertNotIn("driver_phone", new_pkg["allowed_fields"])
        self.assertEqual(new_pkg["status"], "ready")

        # Once the replacement is ready the old artifact is retired, not deleted.
        retired = [p for p in cluster.purpose("safety")["packages"]
                   if p["package_key"] == old_pkg["package_key"]][0]
        self.assertEqual(retired["status"], "retired")
        self.assertIn("audit", retired["retention_note"].lower())
        self.assertFalse(retired["downloadable"])
        # The artifact bytes still exist on the builder store for audit.
        self.assertTrue((cluster.home / "artifacts" / old_pkg["package_key"]).exists())

        # The still-active v1 contract predates the narrowing: no new grant
        # until the consumer renews, even though a current package exists.
        status, payload = cluster.consumer(cluster.token("safety"), "POST",
                                           "/consumer/v1/grants", {"node_id": "node-a"})
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["error"]["code"], "renewal_required")

        status, renewed = cluster.consumer(cluster.token("safety"), "POST",
                                           "/consumer/v1/renew", {"renewal_key": "narrow-renew"})
        self.assertEqual(status, 200, renewed)
        status, payload = cluster.consumer(cluster.token("safety"), "POST",
                                           "/consumer/v1/grants", {"node_id": "node-a"})
        self.assertEqual(status, 200, payload)
        self.assertNotIn("driver_phone", payload["package"]["allowed_fields"])

        stale_request = http("POST", cluster.base + "/edge/v1/authorize", {
            "grant_id": grant_id, "node_id": "node-a",
        }, {"X-Service-Token": SERVICE})
        self.assertEqual(stale_request[0], 200)
        self.assertEqual(stale_request[1]["decision"], "deny")
        self.assertEqual(stale_request[1]["code"], "grant_revoked")

        status, download = cluster.consumer(cluster.token("safety"), "POST", "/consumer/v1/renew",
                                            {"renewal_key": "post-narrow"})
        self.assertEqual(status, 200, download)
        self.assertEqual(download["contract"]["version"], 2)
        self.assertEqual(download["contract"]["change_kind"], "narrowed")
        self.assertNotIn("driver_phone", download["contract"]["allowed_fields"])
        self.assertIn("driver_phone", download["contract"]["disallowed_fields"])

    def test_06_replayed_renewal_key_never_revives_old_contract(self):
        cluster = self.cluster
        first = cluster.renew("finance", "replay-key")
        cluster.wait_package(first["package"]["package_key"])
        fields = [f for f in cluster.purpose("finance")["allowed_fields"] if f != "city"]
        cluster.apply_policy("finance", fields, "narrow for replay test")
        second = cluster.renew("finance", "second-key")
        self.assertGreater(second["contract"]["version"], first["contract"]["version"])

        # Replaying the older key returns the current contract, never the old one.
        replay = cluster.renew("finance", "replay-key")
        self.assertEqual(replay["status"], "renewed")
        self.assertTrue(replay["deduplicated"])
        self.assertEqual(replay["contract"]["version"], second["contract"]["version"])
        self.assertNotIn("city", replay["contract"]["allowed_fields"])
        self.assertNotIn("city", replay["package"]["allowed_fields"])
        self.assertEqual(replay["replayed_contract_version"], 1)

        # Same key, same outcome: no third contract is created.
        again = cluster.renew("finance", "replay-key")
        self.assertEqual(again["contract"]["version"], second["contract"]["version"])

    def test_07_builder_rejects_manifest_field_mismatch(self):
        """A compromised builder cannot complete a job with a wider field set."""
        cluster = self.cluster
        cluster.kill("builder")
        status, payload = cluster.admin("POST", "/api/v1/admin/purposes/finance/rebuild",
                                        {"force": True})
        self.assertEqual(status, 200, payload)
        package = payload["package"]
        # Other purposes may still have queued jobs from earlier tests; lease
        # until the rebuild under test is handed out.
        lease = None
        for _ in range(10):
            lease = http("POST", cluster.base + "/builder/v1/jobs/lease",
                         {"owner": "rogue", "lease_seconds": 2},
                         {"X-Service-Token": SERVICE})[1]["job"]
            if lease and lease["package_key"] == package["package_key"]:
                break
        self.assertIsNotNone(lease)
        self.assertEqual(lease["package_key"], package["package_key"])
        status, failure = http("POST", cluster.base + f"/builder/v1/jobs/{lease['id']}/complete", {
            "lease_token": lease["lease_token"],
            "allowed_fields": lease["allowed_fields"] + ["passenger_name"],
            "manifest": {"package_key": lease["package_key"], "fields": []},
            "content_sha256": "0" * 64, "size_bytes": 10, "row_count": 1,
            "artifact_path": str(cluster.home / "artifacts" / "x.ndjson"),
        }, {"X-Service-Token": SERVICE})
        self.assertEqual(status, 409, failure)
        self.assertEqual(failure["error"]["code"], "manifest_field_mismatch")
        # A malformed completion must not mark the job done.  The rogue lease
        # is still held, so the job is only leasable again once it expires.
        time.sleep(2.3)
        lease_state = http("POST", cluster.base + "/builder/v1/jobs/lease",
                           {"owner": "recovery", "lease_seconds": 1},
                           {"X-Service-Token": SERVICE})[1]["job"]
        self.assertIsNotNone(lease_state, "rejected completion must leave the job leasable")
        cluster.spawn("builder", ["-m", "scopepack.builder.app"])
        cluster._wait(cluster.builder_base + "/healthz", "builder")
        ready = cluster.wait_package(package["package_key"], timeout=40)
        self.assertEqual(ready["status"], "ready")


if __name__ == "__main__":
    unittest.main()


class LateBuildTests(ClusterCase):
    """A build that finishes after its policy was replaced must not go live."""

    cluster_kwargs = {"build_delay_ms": 4000, "lease_seconds": 30}

    def test_late_completion_of_superseded_policy_is_archived_not_published(self):
        cluster = self.cluster
        first = cluster.renew("analytics", "late-build-1")
        old_key = first["package"]["package_key"]
        self.assertIn(first["package"]["status"], ("pending", "building"))

        # Wait until the builder is actually rendering that artifact.
        deadline = time.time() + 10
        while time.time() < deadline:
            current = http("GET", cluster.builder_base + "/healthz")[1].get("current")
            if current and current["package_key"] == old_key:
                break
            time.sleep(0.05)
        else:
            self.fail("builder never started the first artifact")

        # Narrow the policy while the first artifact is still being rendered.
        fields = [f for f in cluster.purpose("analytics")["allowed_fields"] if f != "rating"]
        cluster.apply_policy("analytics", fields, "narrow during build")
        new_key = [p["package_key"] for p in cluster.purpose("analytics")["packages"]
                   if p["package_key"] != old_key][0]

        new_pkg = cluster.wait_package(new_key, timeout=40)
        self.assertEqual(new_pkg["status"], "ready")

        old = [p for p in cluster.purpose("analytics")["packages"]
               if p["package_key"] == old_key][0]
        self.assertEqual(old["status"], "retired", old)
        self.assertFalse(old["downloadable"])
        self.assertIn("superseded policy", old["retention_note"])
        self.assertIn("rating", old["allowed_fields"])
        self.assertNotIn("rating", new_pkg["allowed_fields"])

        # The late artifact is kept for audit under a retired name, and the
        # replacement package was never disturbed by its completion.
        archived = sorted((cluster.home / "artifacts" / old_key).glob("*.retired-*.ndjson"))
        self.assertEqual(len(archived), 1, list((cluster.home / "artifacts" / old_key).iterdir()))
        self.assertGreater(archived[0].stat().st_size, 0)
        status, payload = cluster.admin("GET", f"/api/v1/admin/packages/{old['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["package"]["authorization_basis"]["policy"]["status"], "retired")

        # The still-active contract predates the narrowing, so no grant until
        # a renewal; after renewal the grant points at the replacement package.
        status, payload = cluster.consumer(cluster.token("analytics"), "POST",
                                           "/consumer/v1/grants", {"node_id": "node-a"})
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["error"]["code"], "renewal_required")
        renewed = cluster.renew("analytics", "late-build-2")
        self.assertNotEqual(renewed["package"]["package_key"], old_key)
        self.assertNotIn("rating", renewed["package"]["allowed_fields"])
