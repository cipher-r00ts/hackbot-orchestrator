from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from .util import HackbotError, write_atomic

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    metadata TEXT NOT NULL DEFAULT '{}',
    source_file TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(target_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(target_id, kind);

CREATE TABLE IF NOT EXISTS content (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    source_url TEXT,
    tool TEXT,
    format TEXT,
    item_count INTEGER,
    size INTEGER,
    sha256 TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(asset_id, path)
);
CREATE INDEX IF NOT EXISTS idx_content_asset ON content(asset_id);
CREATE INDEX IF NOT EXISTS idx_content_kind ON content(asset_id, kind);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('gadget', 'lead', 'finding')),
    severity TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    file_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);

CREATE TABLE IF NOT EXISTS finding_assets (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, asset_id)
);
"""

TABLE_ORDER: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("targets", ("id",)),
    ("assets", ("id",)),
    ("content", ("id",)),
    ("findings", ("id",)),
    ("finding_assets", ("finding_id", "asset_id")),
)

GITIGNORE_LINES = (
    "# hackbot local state",
    ".hackbot/hackbot.db",
    ".hackbot/hackbot.db-*",
    ".hackbot/sync.lock",
    ".hackbot/sync.log",
    "",
    "# raw secrets stay local",
    "targets/*/content/**/secrets/",
    "targets/*/findings/**/secrets/",
)


def db_path(root: Path) -> Path:
    return Path(root) / ".hackbot" / "hackbot.db"


def dump_path(root: Path) -> Path:
    return Path(root) / ".hackbot" / "hackbot.sql"


def connect(root: Path) -> sqlite3.Connection:
    root = Path(root)
    hackdir = root / ".hackbot"
    hackdir.mkdir(parents=True, exist_ok=True)
    path = db_path(root)
    fresh = not path.exists() or path.stat().st_size == 0
    dump = dump_path(root)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")

    if fresh and dump.exists():
        try:
            conn.executescript(dump.read_text(encoding="utf-8"))
        except sqlite3.Error as exc:
            conn.close()
            path.unlink(missing_ok=True)
            raise HackbotError(f"could not restore database from {dump}: {exc}") from exc

    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version == 0:
        conn.executescript(SCHEMA_SQL)
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        conn.close()
        raise HackbotError(
            f"database schema version {version} is newer than this hackbot build "
            f"({SCHEMA_VERSION}); upgrade hackbot"
        )

    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, bytes):
        return "X'" + value.hex() + "'"
    text = str(value).replace("'", "''")
    return "'" + text + "'"


def dump_database(conn: sqlite3.Connection, path: Path) -> None:
    """Write a deterministic, text-only snapshot of the database."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    table_data: list[tuple[str, list[str], list[sqlite3.Row]]] = []
    conn.execute("BEGIN")
    try:
        for table, order in TABLE_ORDER:
            columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
            order_sql = ", ".join(order)
            rows = list(
                conn.execute(f"SELECT * FROM {table} ORDER BY {order_sql}").fetchall()
            )
            table_data.append((table, columns, rows))
    finally:
        conn.rollback()

    lines: list[str] = [
        "PRAGMA foreign_keys = OFF;",
        "BEGIN TRANSACTION;",
        SCHEMA_SQL.strip(),
        "",
    ]
    for table, columns, rows in table_data:
        if not rows:
            continue
        columns_sql = ", ".join(columns)
        for row in rows:
            values = ", ".join(_sql_literal(row[column]) for column in columns)
            lines.append(f"INSERT INTO {table} ({columns_sql}) VALUES ({values});")
        lines.append("")
    lines.extend(["COMMIT;", "PRAGMA foreign_keys = ON;", ""])
    write_atomic(path, "\n".join(lines))


def _ensure_gitignore(root: Path) -> None:
    path = Path(root) / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    existing_lines = set(existing.splitlines())
    missing = [line for line in GITIGNORE_LINES if line and line not in existing_lines]
    if not missing:
        return
    prefix = ""
    if existing and not existing.endswith("\n"):
        prefix = "\n"
    addition = "\n".join(missing) + "\n"
    write_atomic(path, existing + prefix + addition)


def _init_git(root: Path) -> None:
    if (Path(root) / ".git").exists():
        return
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "init", "-b", "main"],
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                ["git", "-C", str(root), "init"],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "symbolic-ref", "HEAD", "refs/heads/main"],
                check=True,
                text=True,
                capture_output=True,
            )
    except FileNotFoundError as exc:
        raise HackbotError("git is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise HackbotError(f"could not initialize git repository: {exc}") from exc


def init_root(root: Path) -> dict[str, str]:
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / ".hackbot").mkdir(parents=True, exist_ok=True)
    (root / "targets").mkdir(parents=True, exist_ok=True)
    _ensure_gitignore(root)
    _init_git(root)

    conn = connect(root)
    try:
        dump_database(conn, dump_path(root))
    finally:
        conn.close()

    return {
        "root": str(root),
        "database": str(db_path(root)),
        "snapshot": str(dump_path(root)),
    }
