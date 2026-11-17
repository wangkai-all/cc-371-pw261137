"""Development supervisor: run all four processes and seed state.

Usage:
    python3 -m scopepack.dev up            # foreground, Ctrl-C stops everything
    python3 -m scopepack.dev up --reset    # wipe var/ first
    python3 -m scopepack.dev env           # print shell exports for manual runs

The services are intentionally independent processes.  This helper only makes
the local demo convenient; production deployment would run each module under
its own service manager.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from scopepack.common.config import load_settings
from scopepack.common.seed import seed_everything

ROOT = Path(__file__).resolve().parents[1]


def env_for(settings) -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("SCOPEPACK_HOME", str(settings.home))
    env.setdefault("SCOPEPACK_REGISTRY_BASE", settings.registry_base)
    env.setdefault("SCOPEPACK_BUILDER_BASE", settings.builder_base)
    env.setdefault("SCOPEPACK_REGISTRY_PORT", str(settings.registry_port))
    env.setdefault("SCOPEPACK_BUILDER_PORT", str(settings.builder_port))
    env.setdefault("SCOPEPACK_NODE_A_PORT", str(settings.node_a_port))
    env.setdefault("SCOPEPACK_NODE_B_PORT", str(settings.node_b_port))
    return env


def up(reset: bool) -> int:
    settings = load_settings()
    if reset and settings.home.exists():
        shutil.rmtree(settings.home)
    settings.home.mkdir(parents=True, exist_ok=True)
    dataset = seed_everything(settings)
    env = env_for(settings)
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    commands = [
        ("registry", [sys.executable, "-m", "scopepack.registry.app"], 1.0),
        ("builder", [sys.executable, "-m", "scopepack.builder.app"], 0.2),
        ("edge-a", [sys.executable, "-m", "scopepack.consumer.edge", "--node-id", "node-a"], 0.0),
        ("edge-b", [sys.executable, "-m", "scopepack.consumer.edge", "--node-id", "node-b"], 0.0),
    ]
    processes: list[tuple[str, subprocess.Popen]] = []
    print(f"dataset {dataset['version']} rows={dataset['row_count']}")
    try:
        for name, command, delay in commands:
            if delay:
                time.sleep(delay)
            processes.append((name, subprocess.Popen(command, cwd=ROOT, env=env)))
        print("\nScopepack is up:")
        print(f"  console   http://127.0.0.1:{settings.registry_port}/")
        print(f"  registry  http://127.0.0.1:{settings.registry_port}/healthz")
        print(f"  builder   http://127.0.0.1:{settings.builder_port}/healthz")
        print(f"  edge-a    http://127.0.0.1:{settings.node_a_port}/healthz")
        print(f"  edge-b    http://127.0.0.1:{settings.node_b_port}/healthz")
        print(f"\nadmin token: {settings.admin_token}")
        print("consumer tokens:", settings.home / "consumer-tokens.json")
        print("\nCtrl-C to stop.\n")
        while True:
            for name, process in processes:
                code = process.poll()
                if code is not None:
                    print(f"{name} exited with {code}; shutting down", file=sys.stderr)
                    raise KeyboardInterrupt
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for name, process in processes:
            if process.poll() is None:
                process.terminate()
        deadline = time.time() + 6
        for name, process in processes:
            try:
                process.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                process.kill()
        print("stopped")
    return 0


def print_env() -> int:
    settings = load_settings()
    for key, value in sorted(env_for(settings).items()):
        if key.startswith("SCOPEPACK_"):
            print(f"export {key}={value}")
    print(f"export PYTHONPATH={ROOT}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] not in ("up", "env"):
        print(__doc__)
        return 2
    if argv[0] == "env":
        return print_env()
    return up("--reset" in argv[1:])


if __name__ == "__main__":
    sys.exit(main())
