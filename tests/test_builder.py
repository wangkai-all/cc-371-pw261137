"""Builder resilience: lease expiry, duplicate completion and retry."""
from __future__ import annotations

import time
import unittest

from tests.harness import SERVICE, ClusterCase, http


class BuilderResilienceTests(ClusterCase):
    # A long build delay lets us expire the lease mid-build deterministically.
    cluster_kwargs = {"build_delay_ms": 2500, "lease_seconds": 2}

    def test_lease_expiry_lets_second_builder_finish_without_duplicates(self):
        cluster = self.cluster
        status, payload = cluster.admin("POST", "/api/v1/admin/purposes/finance/rebuild",
                                        {"force": True})
        self.assertEqual(status, 200, payload)
        package_key = payload["package"]["package_key"]

        # Wait until the first builder has leased the job and is mid-render.
        deadline = time.time() + 8
        current = None
        while time.time() < deadline:
            hb = http("GET", cluster.builder_base + "/healthz")[1]
            current = hb.get("current")
            if current:
                break
            time.sleep(0.05)
        self.assertIsNotNone(current, "builder never picked up the job")
        self.assertEqual(current["package_key"], package_key)

        # Simulate a builder crash: no completion, no heartbeat.  The lease is
        # allowed to expire rather than being renewed.
        cluster.kill("builder")
        time.sleep(2.4)

        lease = http("POST", cluster.base + "/builder/v1/jobs/lease",
                     {"owner": "recovery-builder", "lease_seconds": 30},
                     {"X-Service-Token": SERVICE})[1]["job"]
        # The recovery builder may already have leased it; either way the job
        # must be re-leasable and a single artifact must result.
        cluster.spawn("builder", ["-m", "scopepack.builder.app"])
        cluster._wait(cluster.builder_base + "/healthz", "builder")
        ready = cluster.wait_package(package_key, timeout=40)
        self.assertEqual(ready["status"], "ready", ready)
        self.assertGreaterEqual(ready["build_attempts"], 2)

        import sqlite3
        conn = sqlite3.connect(cluster.home / "registry.sqlite3")
        try:
            versions = conn.execute(
                "SELECT COUNT(*) FROM packages WHERE purpose_id=1 AND policy_version_id="
                "(SELECT policy_version_id FROM packages WHERE package_key=?)",
                (package_key,)).fetchone()[0]
            jobs = conn.execute(
                "SELECT status, attempts FROM build_jobs WHERE package_id=?", (ready["id"],)).fetchone()
            done = conn.execute(
                "SELECT COUNT(*) FROM build_jobs WHERE status='done' AND package_id=?",
                (ready["id"],)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(versions, 1, "exactly one package for the purpose+policy")
        self.assertEqual(done, 1)
        self.assertGreaterEqual(jobs[1], 2, "job was attempted by two builders")

    def test_failed_build_is_retryable(self):
        cluster = self.cluster
        status, payload = cluster.admin("POST", "/api/v1/admin/purposes/analytics/rebuild",
                                        {"force": True})
        package = payload["package"]
        # Force the job to fail via the builder-facing endpoint.
        lease = http("POST", cluster.base + "/builder/v1/jobs/lease",
                     {"owner": "fail-tester", "lease_seconds": 10},
                     {"X-Service-Token": SERVICE})[1]["job"]
        self.assertIsNotNone(lease)
        status, _ = http("POST", cluster.base + f"/builder/v1/jobs/{lease['id']}/fail",
                         {"lease_token": lease["lease_token"], "reason": "simulated crash"},
                         {"X-Service-Token": SERVICE})
        self.assertEqual(status, 200)
        failed = cluster.wait_package(package["package_key"])
        self.assertEqual(failed["status"], "failed")
        self.assertIn("simulated crash", failed["failure_reason"])

        status, retry = cluster.admin("POST", "/api/v1/admin/purposes/analytics/rebuild",
                                      {"force": True})
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry["status"], "queued")
        ready = cluster.wait_package(package["package_key"], timeout=40)
        self.assertEqual(ready["status"], "ready")


if __name__ == "__main__":
    unittest.main()
