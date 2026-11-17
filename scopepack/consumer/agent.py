"""Consumer CLI: a small subscription agent used by the demo, tests and the UI.

Commands:
  renew      obtain/renew a contract; prints the resulting package state
  download   download through an edge with digest verification and resume
  ack        submit spooled acknowledgements (safe to retry; deduplicated)
  inspect    show the active contract

Design notes exercised by this agent
------------------------------------
* A renewal carries a caller-supplied ``renewal_key``.  If the caller retries
  after a timeout, the registry returns the original contract instead of
  creating a second one.
* Downloads are written to a ``.part`` file and resumed with a Range request.
  An interrupted stream is never acknowledged; only a verified whole artifact
  produces an ack.  Re-submitting that ack is harmless.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from scopepack.common.config import load_settings
from scopepack.common.http import http_json
from scopepack.common.seed import seed_everything
from scopepack.common.util import canonical_json, new_id


class Interrupted(Exception):
    def __init__(self, message: str, bytes_received: int):
        super().__init__(message)
        self.bytes_received = bytes_received


def read_token(settings, consumer_id: str) -> str:
    seed_everything(settings)
    path = settings.home / "consumer-tokens.json"
    tokens = json.loads(path.read_text(encoding="utf-8"))
    if consumer_id not in tokens:
        raise SystemExit(f"unknown consumer {consumer_id}; known: {sorted(tokens)}")
    return tokens[consumer_id]


def request(method: str, url: str, token: str, body: Any | None = None,
            timeout: float = 15.0, extra_headers: dict[str, str] | None = None) -> tuple[int, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    headers.update(extra_headers or {})
    return http_json(method, url, body, headers=headers, timeout=timeout)


def cmd_renew(settings, consumer_id: str, renewal_key: str | None, note: str) -> int:
    token = read_token(settings, consumer_id)
    status, payload = request("POST", settings.registry_base + "/consumer/v1/renew", token, {
        "renewal_key": renewal_key or new_id("renew"), "note": note or "consumer renewal",
    })
    print(json.dumps({"http_status": status, "response": payload}, indent=2, sort_keys=True))
    return 0 if status < 400 else 1


def cmd_inspect(settings, consumer_id: str) -> int:
    token = read_token(settings, consumer_id)
    status, payload = request("GET", settings.registry_base + "/consumer/v1/contract", token)
    print(json.dumps({"http_status": status, "response": payload}, indent=2, sort_keys=True))
    return 0 if status < 400 else 1


def download_once(settings, token: str, edge_base: str, grant_id: str, target: Path,
                  part: Path, max_bytes: int | None = None) -> dict[str, Any]:
    """One attempt.  Resumes from any bytes already in ``part``."""
    offset = part.stat().st_size if part.exists() else 0
    request_obj = urllib.request.Request(
        f"{edge_base}/downloads",
        data=canonical_json({"grant_id": grant_id}).encode(),
        method="POST",
    )
    request_obj.add_header("Authorization", f"Bearer {token}")
    request_obj.add_header("Content-Type", "application/json")
    if offset:
        request_obj.add_header("Range", f"bytes={offset}-")
    received = 0
    try:
        with urllib.request.urlopen(request_obj, timeout=180) as response, part.open("ab") as out:
            while True:
                if max_bytes is not None and received >= max_bytes:
                    raise Interrupted(f"stopped after {received} bytes (test throttle)", received)
                chunk = response.read(4096)
                if not chunk:
                    break
                out.write(chunk)
                received += len(chunk)
            headers = {k.lower(): v for k, v in response.getheaders()}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise SystemExit(json.dumps({"http_status": exc.code, "error": raw}, indent=2))
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise Interrupted(f"network: {type(exc).__name__}: {exc}", received) from exc
    return {"headers": headers, "received": received, "offset": offset}


def cmd_download(settings, consumer_id: str, node: str, out_dir: Path,
                 issue_key: str | None, ack: bool, resume_attempts: int = 0,
                 wait_seconds: float = 20.0) -> int:
    token = read_token(settings, consumer_id)
    edge_base = f"http://127.0.0.1:{settings.node_a_port if node == 'node-a' else settings.node_b_port}"
    body = {"node_id": node, "issue_key": issue_key or new_id("issue")}
    status, grant_payload = request("POST", settings.registry_base + "/consumer/v1/grants", token, body)
    # A fresh renewal returns before the artifact exists.  Waiting here mirrors
    # what a real client does instead of treating "still building" as fatal.
    deadline = time.monotonic() + wait_seconds
    while (status == 409 and (grant_payload.get("error") or {}).get("code") == "package_not_ready"
           and time.monotonic() < deadline):
        time.sleep(0.25)
        status, grant_payload = request("POST", settings.registry_base + "/consumer/v1/grants",
                                        token, body)
    if status >= 400:
        print(json.dumps({"http_status": status, "response": grant_payload}, indent=2), file=sys.stderr)
        return 1
    grant = grant_payload["grant"]
    package = grant_payload["package"]
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{package['package_key']}.ndjson"
    part = out_dir / f"{package['package_key']}.part"
    attempt = 0
    started = time.monotonic()
    while True:
        try:
            download_once(settings, token, edge_base, grant["grant_id"], target, part)
            break
        except Interrupted as exc:
            attempt += 1
            print(json.dumps({"interrupted": str(exc), "resume_attempt": attempt,
                              "partial_bytes": part.stat().st_size if part.exists() else 0}),
                  file=sys.stderr)
            if attempt > resume_attempts:
                return 3
            # Resuming needs a fresh grant if the old one expired; hammering the
            # same grant is itself a test of mid-stream expiry handling.
            time.sleep(0.3)
            status, refreshed = request("POST", settings.registry_base + "/consumer/v1/grants", token, {
                "node_id": node, "issue_key": f"{issue_key or 'auto'}-resume{attempt}",
            })
            if status >= 400:
                print(json.dumps({"http_status": status, "response": refreshed}, indent=2), file=sys.stderr)
                return 1
            grant = refreshed["grant"]
    digest = hashlib.sha256()
    with part.open("rb") as handle:
        while True:
            block = handle.read(1 << 16)
            if not block:
                break
            digest.update(block)
    actual = digest.hexdigest()
    downloaded = part.stat().st_size
    elapsed = max(0.001, time.monotonic() - started)
    verified = actual == package["content_sha256"]
    result = {
        "consumer": consumer_id, "node": node, "package_key": package["package_key"],
        "bytes": downloaded, "sha256": actual, "expected_sha256": package["content_sha256"],
        "verified": verified, "elapsed_s": round(elapsed, 3),
        "fields": package["allowed_fields"],
    }
    if not verified:
        part.unlink(missing_ok=True)
        print(json.dumps(result | {"error": "digest mismatch; artifact deleted"}, indent=2))
        return 4
    part.replace(target)
    print(json.dumps(result, indent=2, sort_keys=True))
    if ack:
        ack_dir = settings.home / "ack-spool" / consumer_id
        ack_dir.mkdir(parents=True, exist_ok=True)
        ack_payload = {
            "ack_id": "ack-%s" % (issue_key or new_id("x")),
            "grant_id": grant["grant_id"], "package_key": package["package_key"],
            "sha256": actual, "bytes": downloaded, "node_id": node,
        }
        path = ack_dir / f"{ack_payload['ack_id']}.json"
        path.write_text(json.dumps(ack_payload, indent=2))
        print(f"ack spooled at {path}")
    return 0


def cmd_ack(settings, consumer_id: str, submit: bool, target: list[str] | None = None) -> int:
    token = read_token(settings, consumer_id)
    ack_dir = settings.home / "ack-spool" / consumer_id
    if not ack_dir.exists():
        print("no spooled acknowledgements")
        return 0
    results = []
    paths = [Path(p) for p in target] if target else sorted(ack_dir.glob("*.json"))
    for path in paths:
        ack = json.loads(path.read_text(encoding="utf-8"))
        if not submit:
            results.append({"ack_id": ack["ack_id"], "would_submit": True})
            continue
        status, payload = request("POST", settings.registry_base + "/edge/v1/acks", token, {
            "ack_id": ack["ack_id"], "grant_id": ack["grant_id"],
            "sha256": ack["sha256"], "bytes": ack["bytes"], "node_id": ack["node_id"],
        })
        results.append({"ack_id": ack["ack_id"], "http_status": status, "response": payload})
        if status < 400:
            path.unlink(missing_ok=True)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scopepack-consumer")
    parser.add_argument("--consumer", default="finance")
    sub = parser.add_subparsers(dest="command", required=True)
    renew = sub.add_parser("renew")
    renew.add_argument("--renewal-key", default=None)
    renew.add_argument("--note", default="")
    dl = sub.add_parser("download")
    dl.add_argument("--node", choices=["node-a", "node-b"], default="node-a")
    dl.add_argument("--out", default="downloads")
    dl.add_argument("--issue-key", default=None)
    dl.add_argument("--no-ack", action="store_true")
    dl.add_argument("--resume-attempts", type=int, default=0)
    dl.add_argument("--wait-seconds", type=float, default=20.0,
                    help="how long to wait for a freshly queued package build")
    ack = sub.add_parser("ack")
    ack.add_argument("--dry-run", action="store_true")
    ack.add_argument("--file", action="append", default=None)
    sub.add_parser("inspect")
    args = parser.parse_args(argv)
    settings = load_settings()
    if args.command == "renew":
        return cmd_renew(settings, args.consumer, args.renewal_key, args.note)
    if args.command == "inspect":
        return cmd_inspect(settings, args.consumer)
    if args.command == "download":
        return cmd_download(settings, args.consumer, args.node, Path(args.out),
                            args.issue_key, ack=not args.no_ack,
                            resume_attempts=args.resume_attempts,
                            wait_seconds=args.wait_seconds)
    if args.command == "ack":
        return cmd_ack(settings, args.consumer, submit=not args.dry_run, target=args.file)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
