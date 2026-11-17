"""Delivery-path tests: caching, mid-stream revocation, resume and acks."""
from __future__ import annotations

import hashlib
import json
import time
import unittest

from tests.harness import SERVICE, Cluster, ClusterCase, http


class DeliveryTests(ClusterCase):
    cluster_kwargs = {"chunk_bytes": 4096, "chunk_delay_ms": 0, "recheck_ms": 100}

    def test_01_edge_cache_is_scoped_to_the_contract(self):
        cluster = self.cluster
        payload = cluster.renew("finance", "cache-1")
        package = cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("finance", key="cache-grant")
        self.assertEqual(status, 200, grant)
        code, body, headers = cluster.download("finance", grant["grant"]["grant_id"], cluster.node_a)
        self.assertEqual(code, 200)
        self.assertEqual(hashlib.sha256(body).hexdigest(), package["content_sha256"])
        self.assertEqual(headers["x-package-fields"].split(","), package["allowed_fields"])

        cache = cluster.edge_cache(cluster.node_a)
        cached = cache["state"]["packages"][package["package_key"]]
        cached_fields = [f["name"] for f in cached["manifest"]["fields"]]
        self.assertEqual(cached_fields, package["allowed_fields"])
        on_disk = json.loads(
            (cluster.home / "edges" / "node-a" / "artifacts" / f"{package['package_key']}.ndjson")
            .read_text().splitlines()[0])
        self.assertEqual(set(on_disk), set(package["allowed_fields"]))
        self.assertNotIn("passenger_name", on_disk)

    def test_03_download_resumes_with_range(self):
        cluster = self.cluster
        payload = cluster.renew("finance", "resume-1")
        package = cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("finance", key="resume-grant")
        self.assertEqual(status, 200, grant)
        first_status, first, headers = cluster.download(
            "finance", grant["grant"]["grant_id"], cluster.node_a, max_bytes=25000)
        self.assertEqual(first_status, 200)
        self.assertEqual(len(first), 25000)
        self.assertEqual(headers["accept-ranges"], "bytes")

        status, grant2 = cluster.grant("finance", key="resume-grant-2")
        second_status, second, headers2 = cluster.download(
            "finance", grant2["grant"]["grant_id"], cluster.node_a, range_start=len(first))
        self.assertEqual(second_status, 206)
        self.assertEqual(headers2["content-range"],
                         f"bytes {len(first)}-{package['size_bytes'] - 1}/{package['size_bytes']}")
        combined = first + second
        self.assertEqual(len(combined), package["size_bytes"])
        self.assertEqual(hashlib.sha256(combined).hexdigest(), package["content_sha256"])

    def test_04_ack_is_idempotent_and_scoped(self):
        cluster = self.cluster
        payload = cluster.renew("finance", "ack-1")
        cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("finance", key="ack-grant")
        self.assertEqual(status, 200, grant)
        grant_id = grant["grant"]["grant_id"]
        package = grant["package"]
        code, body, _ = cluster.download("finance", grant_id, cluster.node_a)
        self.assertEqual(code, 200)
        ack = {
            "ack_id": "ack-duplicate-1", "grant_id": grant_id,
            "sha256": package["content_sha256"], "bytes": len(body), "node_id": "node-a",
        }
        first = cluster.consumer(cluster.token("finance"), "POST", "/edge/v1/acks", ack)
        self.assertEqual(first[0], 200, first)
        self.assertEqual(first[1]["classification"], "current")
        self.assertTrue(first[1]["counts_current"])
        second = cluster.consumer(cluster.token("finance"), "POST", "/edge/v1/acks", ack)
        self.assertEqual(second[0], 200)
        self.assertEqual(second[1]["status"], "duplicate")

        # Another consumer cannot acknowledge this grant.
        other = cluster.consumer(cluster.token("safety"), "POST", "/edge/v1/acks", ack)
        self.assertEqual(other[0], 403, other)
        self.assertEqual(other[1]["error"]["code"], "ack_forbidden")

        # Tampered digest is quarantined rather than counted.
        bad = dict(ack, ack_id="ack-bad-digest", sha256="f" * 64)
        status, payload = cluster.consumer(cluster.token("finance"), "POST", "/edge/v1/acks", bad)
        self.assertEqual(status, 200)
        self.assertEqual(payload["classification"], "integrity_mismatch")
        self.assertFalse(payload["counts_current"])

    def test_05_old_consumer_ack_is_retained_not_counted(self):
        cluster = self.cluster
        payload = self.cluster.renew("finance", "old-ack-1")
        cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("finance", key="old-ack-grant")
        grant_id = grant["grant"]["grant_id"]
        package = grant["package"]
        code, body, _ = cluster.download("finance", grant_id, cluster.node_a)
        self.assertEqual(code, 200)

        # Narrow the purpose; the old package is retired and its grant revoked.
        fields = [f for f in cluster.purpose("finance")["allowed_fields"] if f != "city"]
        cluster.apply_policy("finance", fields, "remove city")
        new_key = [p for p in cluster.purpose("finance")["packages"]
                   if p["package_key"] != package["package_key"]][0]["package_key"]
        cluster.wait_package(new_key)

        ack = {
            "ack_id": "ack-old-1", "grant_id": grant_id,
            "sha256": package["content_sha256"], "bytes": len(body), "node_id": "node-a",
        }
        status, payload = cluster.consumer(cluster.token("finance"), "POST", "/edge/v1/acks", ack)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["classification"], "historic_retained")
        self.assertTrue(payload["retained"])
        self.assertFalse(payload["counts_current"])

        # Duplicate replay of the old ack is still classified the same way.
        again = cluster.consumer(cluster.token("finance"), "POST", "/edge/v1/acks", ack)
        self.assertEqual(again[0], 200)
        self.assertEqual(again[1]["status"], "duplicate")

    def test_06_cache_purged_before_next_download(self):
        cluster = self.cluster
        payload = cluster.renew("safety", "purge-1")
        package = cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("safety", key="purge-grant")
        code, _, _ = cluster.download("safety", grant["grant"]["grant_id"], cluster.node_a)
        self.assertEqual(code, 200)
        self.assertIn(package["package_key"], cluster.edge_cache(cluster.node_a)["state"]["packages"])

        fields = [f for f in cluster.purpose("safety")["allowed_fields"] if f != "gps_trace"]
        cluster.apply_policy("safety", fields, "remove gps")
        deadline = time.time() + 8
        while time.time() < deadline:
            if package["package_key"] not in cluster.edge_cache(cluster.node_a)["state"]["packages"]:
                break
            time.sleep(0.2)
        self.assertNotIn(package["package_key"], cluster.edge_cache(cluster.node_a)["state"]["packages"])


class MidstreamTests(ClusterCase):
    # Slow chunks guarantee several recheck windows during one download.
    cluster_kwargs = {"chunk_bytes": 1024, "chunk_delay_ms": 10, "recheck_ms": 100}

    def test_02_midstream_narrowing_aborts_slow_download(self):
        cluster = self.cluster
        # A slow edge would take many seconds for this package.
        payload = cluster.renew("analytics", "midstream-1")
        package = cluster.wait_package(payload["package"]["package_key"])
        self.assertEqual(package["status"], "ready")
        status, grant = cluster.grant("analytics", key="midstream-grant")
        self.assertEqual(status, 200, grant)
        grant_id = grant["grant"]["grant_id"]

        import urllib.request
        request = urllib.request.Request(
            cluster.node_b + "/downloads",
            data=json.dumps({"grant_id": grant_id}).encode(), method="POST")
        request.add_header("Authorization", f"Bearer {cluster.token('analytics')}")
        request.add_header("Content-Type", "application/json")
        received = 0
        aborted = False
        changed = False
        with urllib.request.urlopen(request, timeout=30) as response:
            try:
                while received < package["size_bytes"]:
                    block = response.read(1024)
                    if not block:
                        break
                    received += len(block)
                    if received > 20000 and not changed:
                        changed = True
                        fields = [f for f in cluster.purpose("analytics")["allowed_fields"]
                                  if f != "city"]
                        cluster.apply_policy("analytics", fields, "remove city mid-stream")
            except Exception:
                aborted = True
        # Depending on the HTTP client the truncated stream surfaces either as
        # an exception or as an early EOF; what matters is that it did not
        # complete and the edge recorded the termination.
        self.assertLess(received, package["size_bytes"])

        events = cluster.edge_cache(cluster.node_b)["state"]
        self.assertEqual(events["packages"], {})
        purges = events.get("purges", [])
        self.assertTrue(any(p["package_key"] == package["package_key"] for p in purges))
        # The stream must have been recorded as aborted, and never completed.
        sql = "SELECT event, bytes FROM download_events WHERE grant_id=? ORDER BY id"
        rows = []
        import sqlite3
        conn = sqlite3.connect(cluster.home / "registry.sqlite3")
        try:
            rows = conn.execute(sql, (grant_id,)).fetchall()
        finally:
            conn.close()
        names = [r[0] for r in rows]
        self.assertIn("stream_aborted", names)
        self.assertNotIn("stream_complete", names)


class GrantExpiryTests(ClusterCase):
    cluster_kwargs = {"grant_ttl": 3, "chunk_bytes": 2048, "chunk_delay_ms": 4, "recheck_ms": 100}

    def test_expired_grant_cannot_start_download(self):
        cluster = self.cluster
        payload = cluster.renew("finance", "expiry-1")
        package = cluster.wait_package(payload["package"]["package_key"])
        status, grant = cluster.grant("finance", key="expiry-grant")
        self.assertEqual(status, 200, grant)
        time.sleep(3.4)
        code, body, _ = None, None, None
        with self.assertRaises(Exception) as caught:
            cluster.download("finance", grant["grant"]["grant_id"], cluster.node_a)
        import urllib.error
        self.assertIsInstance(caught.exception, urllib.error.HTTPError)
        self.assertEqual(caught.exception.code, 403)
        payload = json.loads(caught.exception.read())
        self.assertEqual(payload["error"]["code"], "grant_expired")


if __name__ == "__main__":
    unittest.main()
