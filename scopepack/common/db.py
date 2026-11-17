"""SQLite access helpers.

The registry is the only writer of the control-plane database.  The builder and
the download edges talk to it over HTTP, never by opening the file directly.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .util import now_iso


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "registry" / "schema.sql"


class TxConnection(sqlite3.Connection):
    """Connection that remembers how deeply nested the transaction scope is."""

    tx_depth: int = 0


def connect(db_path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        f"file:{db_path}?mode={'ro' if readonly else 'rwc'}",
        uri=True,
        timeout=15.0,
        isolation_level=None,
        check_same_thread=False,
        factory=TxConnection,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Nestable transaction scope.

    The outermost scope takes the write lock with BEGIN IMMEDIATE; nested
    scopes use SAVEPOINTs so helpers such as ensure_package() can be called
    both standalone and from inside a larger unit of work.
    """
    depth = int(getattr(conn, "tx_depth", 0))
    savepoint = f"scopepack_sp_{depth}"
    if depth == 0:
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.execute(f"SAVEPOINT {savepoint}")
    conn.tx_depth = depth + 1
    try:
        yield conn
    except BaseException:
        if depth == 0:
            conn.execute("ROLLBACK")
        else:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    else:
        if depth == 0:
            conn.execute("COMMIT")
        else:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    finally:
        conn.tx_depth = depth


def initialize(db_path: Path) -> sqlite3.Connection:
    conn = connect(db_path)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    with transaction(conn):
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
            ("1",),
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('initialized_at', ?)",
            (now_iso(),),
        )
    return conn
