from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__, db as dbmod, git_sync
from .render import print_json, print_table
from .util import (
    ASSET_KINDS,
    CONTENT_KINDS,
    CONTENT_KIND_DIRS,
    FINDING_TYPES,
    HackbotError,
    asset_kind_and_value,
    copy_atomic,
    count_items,
    detect_format,
    ensure_within,
    format_bytes,
    json_dumps,
    normalize_asset_value,
    now_iso,
    parse_json_object,
    parse_json_text,
    read_text_file,
    relative_to_root,
    resolve_root,
    safe_asset_dir,
    sha256_file,
    target_content_dir,
    target_dir,
    validate_target_name,
    write_atomic,
)

KNOWN_COMMANDS = {
    "help",
    "init",
    "targets",
    "findings",
    "target",
    "finding",
    "asset",
    "assets",
    "content",
    "sync",
}

FINDING_TEMPLATE = """# {title}

## Summary

## Steps to reproduce

## Impact

## Evidence

## Remediation
"""


def _extract_root(argv: list[str]) -> tuple[str | None, list[str]]:
    root: str | None = None
    cleaned: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--root":
            if index + 1 >= len(argv):
                raise HackbotError("--root requires a path")
            root = argv[index + 1]
            index += 2
        elif arg.startswith("--root="):
            root = arg.split("=", 1)[1]
            index += 1
        else:
            cleaned.append(arg)
            index += 1
    return root, cleaned


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--scope",
        help="scope text, or '-' to read it from stdin",
    )
    group.add_argument(
        "--scope-file",
        help="read scope from a file, or '-' for stdin",
    )


def _add_finding_list_args(
    parser: argparse.ArgumentParser, *, include_target: bool = False
) -> None:
    parser.add_argument("--page", type=int, default=1, help="page number (default: 1)")
    parser.add_argument("--limit", type=int, default=20, help="rows per page (default: 20)")
    if include_target:
        parser.add_argument("--target", help="filter by target name")
    parser.add_argument("--type", choices=FINDING_TYPES, help="filter by finding type")
    parser.add_argument("--status", help="filter by status")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--path", action="store_true", help="print only the local path")
    selector.add_argument("--url", action="store_true", help="print only the GitHub URL")


def _add_content_write_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="target name")
    parser.add_argument("asset", help="asset value, optionally kind:value")
    parser.add_argument("kind", choices=CONTENT_KINDS, help="content file kind")
    parser.add_argument("file", help="file to register or import")
    parser.add_argument("--url", dest="source_url", help="original URL for this file")
    parser.add_argument("--tool", help="tool that produced the file")
    parser.add_argument("--format", dest="file_format", help="override detected format")
    parser.add_argument("--meta", help="extra metadata as a JSON object")
    parser.add_argument("--name", help="destination filename for import")
    parser.add_argument("--force", action="store_true", help="overwrite an existing import")
    parser.add_argument("--json", action="store_true", help="emit JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hackbot",
        description=(
            "Filesystem-first bug bounty manager. Targets, findings, and recon "
            "files live in a Git-backed directory; SQLite indexes the data."
        ),
        epilog=(
            "Examples:\n"
            "  hackbot targets\n"
            "  hackbot findings\n"
            "  hackbot findings F-0001\n"
            "  hackbot findings F-0001 --path\n"
            "  hackbot findings F-0001 --url\n"
            "  hackbot acme findings\n"
            "  hackbot target add acme --scope-file scope.txt\n"
            "\n"
            "The data root defaults to ~/BugBounty. Override it with HACKBOT_ROOT "
            "or --root."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"hackbot {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    subparsers.add_parser("help", help="show this help menu")

    init_parser = subparsers.add_parser("init", help="initialize the data root")
    init_parser.add_argument(
        "--install-cron",
        action="store_true",
        help="install the 15-minute sync cron entry",
    )

    subparsers.add_parser("targets", help="list target names")

    findings_parser = subparsers.add_parser("findings", help="list findings or show one")
    findings_parser.add_argument("finding_id", nargs="?", help="finding id, e.g. F-0001")
    _add_finding_list_args(findings_parser, include_target=True)

    target_parser = subparsers.add_parser("target", help="manage targets")
    target_sub = target_parser.add_subparsers(dest="target_command", required=True)

    target_add = target_sub.add_parser("add", help="create a target")
    target_add.add_argument("name")
    _add_scope_args(target_add)
    target_add.add_argument("--json", action="store_true")

    target_show = target_sub.add_parser("show", help="show target metadata and scope")
    target_show.add_argument("name")
    target_show.add_argument("--json", action="store_true")

    target_update = target_sub.add_parser("update", help="update target metadata")
    target_update.add_argument("name")
    _add_scope_args(target_update)
    target_update.add_argument("--json", action="store_true")

    finding_parser = subparsers.add_parser("finding", help="manage findings")
    finding_sub = finding_parser.add_subparsers(dest="finding_command", required=True)

    finding_add = finding_sub.add_parser("add", help="create a finding")
    finding_add.add_argument("target")
    finding_add.add_argument("--title", required=True)
    finding_add.add_argument("--type", choices=FINDING_TYPES, default="finding")
    finding_add.add_argument("--severity")
    finding_add.add_argument("--status", default="open")
    finding_add.add_argument("--asset", action="append", default=[])
    finding_add.add_argument("--body-file", help="markdown report body, or '-' for stdin")
    finding_add.add_argument("--json", action="store_true")

    finding_update = finding_sub.add_parser("update", help="update a finding")
    finding_update.add_argument("finding_id")
    finding_update.add_argument("--title")
    finding_update.add_argument("--type", choices=FINDING_TYPES)
    finding_update.add_argument("--severity")
    finding_update.add_argument("--status")
    finding_update.add_argument("--asset", action="append")
    finding_update.add_argument("--body-file", help="markdown report body, or '-' for stdin")
    finding_update.add_argument("--json", action="store_true")

    asset_parser = subparsers.add_parser("asset", help="manage assets")
    asset_sub = asset_parser.add_subparsers(dest="asset_command", required=True)

    asset_add = asset_sub.add_parser("add", help="add or update one asset")
    asset_add.add_argument("target")
    asset_add.add_argument("kind", choices=ASSET_KINDS)
    asset_add.add_argument("value")
    asset_add.add_argument("--status")
    asset_add.add_argument("--meta", help="extra metadata as a JSON object")
    asset_add.add_argument("--source-file")
    asset_add.add_argument("--json", action="store_true")

    asset_import = asset_sub.add_parser("import", help="import assets from a file")
    asset_import.add_argument("target")
    asset_import.add_argument("kind", choices=ASSET_KINDS)
    asset_import.add_argument("file")
    asset_import.add_argument("--format", choices=("lines", "httpx"), default="lines")
    asset_import.add_argument("--json", action="store_true")

    assets_parser = subparsers.add_parser("assets", help="list assets for a target")
    assets_parser.add_argument("target")
    assets_parser.add_argument("--kind", choices=ASSET_KINDS)
    assets_parser.add_argument("--status")
    assets_parser.add_argument("--json", action="store_true")

    content_parser = subparsers.add_parser("content", help="manage content files")
    content_sub = content_parser.add_subparsers(dest="content_command", required=True)

    content_list = content_sub.add_parser("list", help="list content files for an asset")
    content_list.add_argument("asset")
    content_list.add_argument("--target", help="disambiguate asset when needed")
    content_list.add_argument("--kind", choices=CONTENT_KINDS)
    content_list.add_argument("--json", action="store_true")

    content_add = content_sub.add_parser("add", help="register an existing file")
    _add_content_write_args(content_add)

    content_import = content_sub.add_parser(
        "import", help="copy a file into the content directory"
    )
    _add_content_write_args(content_import)

    sync_parser = subparsers.add_parser("sync", help="dump the DB and sync with Git")
    sync_parser.add_argument(
        "--install-cron",
        action="store_true",
        help="install the 15-minute sync cron entry",
    )

    return parser


def _read_scope(args: argparse.Namespace) -> str:
    scope_file = getattr(args, "scope_file", None)
    scope = getattr(args, "scope", None)
    if scope_file:
        return read_text_file(scope_file).strip()
    if scope is not None:
        if scope == "-":
            return sys.stdin.read().strip()
        return scope.strip()
    return ""


def _target_row(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM targets WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise HackbotError(f"target '{name}' not found")
    return row


def _resolve_finding(conn: sqlite3.Connection, value: str) -> sqlite3.Row:
    text = (value or "").strip()
    if text.lower().endswith(".md"):
        text = text[:-3]
    upper = text.upper()
    number = upper[2:] if upper.startswith("F-") else upper
    if not number.isdigit():
        raise HackbotError(f"invalid finding id '{value}'")
    finding_id = f"F-{int(number):04d}"
    row = conn.execute(
        """
        SELECT f.*, t.name AS target_name
        FROM findings f
        JOIN targets t ON t.id = f.target_id
        WHERE f.id = ?
        """,
        (finding_id,),
    ).fetchone()
    if row is None:
        raise HackbotError(f"finding '{finding_id}' not found")
    return row


def _assets_for_finding(conn: sqlite3.Connection, finding_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT a.id, a.kind, a.value
            FROM assets a
            JOIN finding_assets fa ON fa.asset_id = a.id
            WHERE fa.finding_id = ?
            ORDER BY a.value COLLATE NOCASE
            """,
            (finding_id,),
        ).fetchall()
    )


def _upsert_asset(
    conn: sqlite3.Connection,
    target_id: int,
    kind: str,
    value: str,
    *,
    status: str | None = None,
    metadata: dict[str, Any] | None = None,
    source_file: str | None = None,
) -> tuple[int, str]:
    now = now_iso()
    row = conn.execute(
        "SELECT id FROM assets WHERE target_id = ? AND kind = ? AND value = ?",
        (target_id, kind, value),
    ).fetchone()
    if row is not None:
        sets = ["last_seen = ?"]
        params: list[Any] = [now]
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if metadata is not None:
            sets.append("metadata = ?")
            params.append(json_dumps(metadata))
        if source_file is not None:
            sets.append("source_file = ?")
            params.append(source_file)
        params.append(row["id"])
        conn.execute(f"UPDATE assets SET {', '.join(sets)} WHERE id = ?", params)
        return int(row["id"]), "updated"

    metadata_text = json_dumps(metadata or {})
    cursor = conn.execute(
        """
        INSERT INTO assets
            (target_id, kind, value, status, metadata, source_file, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_id,
            kind,
            value,
            status or "unknown",
            metadata_text,
            source_file,
            now,
            now,
        ),
    )
    return int(cursor.lastrowid), "added"


def _ensure_asset(
    conn: sqlite3.Connection,
    target_id: int,
    spec: str,
    *,
    status: str | None = None,
    metadata: dict[str, Any] | None = None,
    source_file: str | None = None,
) -> tuple[int, str, str, str]:
    kind, raw_value = asset_kind_and_value(spec)
    value = normalize_asset_value(kind, raw_value)
    explicit_kind = (
        ":" in spec
        and spec.split(":", 1)[0] in ASSET_KINDS
        and spec.split(":", 1)[1] != ""
    )
    if explicit_kind:
        rows = list(
            conn.execute(
                "SELECT * FROM assets WHERE target_id = ? AND kind = ? AND value = ?",
                (target_id, kind, value),
            ).fetchall()
        )
    else:
        rows = list(
            conn.execute(
                "SELECT * FROM assets WHERE target_id = ? AND value = ? ORDER BY id",
                (target_id, value),
            ).fetchall()
        )
    if rows:
        preferred = next((row for row in rows if row["kind"] == kind), rows[0])
        asset_id, action = _upsert_asset(
            conn,
            target_id,
            preferred["kind"],
            preferred["value"],
            status=status,
            metadata=metadata,
            source_file=source_file,
        )
        return asset_id, preferred["kind"], preferred["value"], action
    asset_id, action = _upsert_asset(
        conn,
        target_id,
        kind,
        value,
        status=status,
        metadata=metadata,
        source_file=source_file,
    )
    return asset_id, kind, value, action


def _next_finding_id(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        """
        SELECT COALESCE(MAX(CAST(SUBSTR(id, 3) AS INTEGER)), 0)
        FROM findings
        WHERE id GLOB 'F-[0-9]*'
        """
    ).fetchone()
    return f"F-{int(row[0]) + 1:04d}"


def _stored_source_path(root: Path, value: str | None) -> str | None:
    if not value:
        return None
    path = Path(value).expanduser()
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _archive_recon_file(root: Path, tdir: Path, src: Path) -> tuple[Path, str]:
    try:
        rel = src.resolve().relative_to(tdir.resolve())
    except ValueError:
        pass
    else:
        return src, (Path("targets") / tdir.name / rel).as_posix()

    dest_dir = tdir / "artifacts" / "recon"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    if dest.exists() and sha256_file(dest) != sha256_file(src):
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        dest = dest_dir / f"{src.stem}-{stamp}{src.suffix}"
    copy_atomic(src, dest)
    return dest, relative_to_root(dest, root)


def _read_httpx(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HackbotError(f"invalid httpx JSON: {exc}") from exc
        if not isinstance(data, list):
            raise HackbotError("httpx JSON must be an array or JSONL objects")
        return [item for item in data if isinstance(item, dict)]
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(data, dict):
                return [data]
    objects: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HackbotError(f"invalid httpx JSONL line: {exc}") from exc
        if isinstance(item, dict):
            objects.append(item)
    return objects


def _host_from_httpx(item: dict[str, Any]) -> str | None:
    value = item.get("url") or item.get("host") or item.get("input")
    if not value:
        return None
    value = str(value).strip()
    if "://" in value:
        return urlsplit(value).hostname
    return urlsplit("//" + value).hostname


def _httpx_metadata(item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "status_code",
        "title",
        "tech",
        "webserver",
        "content_type",
        "content_length",
        "cname",
        "ip",
        "ports",
        "cdn_name",
        "cdn_type",
    )
    return {key: item[key] for key in keys if key in item}


def cmd_init(root: Path, args: argparse.Namespace) -> int:
    info = dbmod.init_root(root)
    print(f"Initialized data root: {info['root']}")
    print(f"Database: {info['database']}")
    print(f"Snapshot: {info['snapshot']}")

    conn = dbmod.connect(root)
    try:
        tracked = {
            row["name"]
            for row in conn.execute("SELECT name FROM targets").fetchall()
        }
    finally:
        conn.close()
    if (root / "targets").exists():
        untracked = sorted(
            path.name
            for path in (root / "targets").iterdir()
            if path.is_dir() and path.name not in tracked
        )
        if untracked:
            print("Untracked target directories (left untouched):")
            for name in untracked:
                print(f"  - {name}")
    if args.install_cron:
        git_sync.install_cron(root)
    print("Next: hackbot target add <name>")
    return 0


def cmd_targets(root: Path, conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        "SELECT name FROM targets ORDER BY name COLLATE NOCASE"
    ).fetchall()
    if not rows:
        print("No targets.", file=sys.stderr)
        return 0
    for row in rows:
        print(row["name"])
    return 0


def cmd_target_add(root: Path, conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    name = validate_target_name(args.name)
    scope = _read_scope(args)
    existing = conn.execute("SELECT id FROM targets WHERE name = ?", (name,)).fetchone()
    if existing is not None:
        raise HackbotError(f"target '{name}' already exists in the database")
    tdir = target_dir(root, name)
    if tdir.exists():
        raise HackbotError(f"directory already exists: {tdir}")

    tdir.mkdir(parents=True, exist_ok=False)
    try:
        for rel in (
            "findings",
            "content",
            "artifacts/recon",
            "artifacts/analysis",
            "artifacts/reports",
        ):
            (tdir / rel).mkdir(parents=True, exist_ok=True)
        now = now_iso()
        with conn:
            conn.execute(
                "INSERT INTO targets (name, scope, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (name, scope, now, now),
            )
    except BaseException:
        shutil.rmtree(tdir, ignore_errors=True)
        raise

    if args.json:
        print_json({"name": name, "scope": scope, "path": str(tdir)})
    else:
        print(f"Created target '{name}' at {tdir}")
    return 0


def cmd_target_show(root: Path, conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    row = _target_row(conn, args.name)
    tdir = target_dir(root, row["name"])
    asset_count = conn.execute(
        "SELECT COUNT(*) FROM assets WHERE target_id = ?", (row["id"],)
    ).fetchone()[0]
    content_count = conn.execute(
        """
        SELECT COUNT(*) FROM content c
        JOIN assets a ON a.id = c.asset_id
        WHERE a.target_id = ?
        """,
        (row["id"],),
    ).fetchone()[0]
    finding_count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE target_id = ?", (row["id"],)
    ).fetchone()[0]

    if args.json:
        print_json(
            {
                "name": row["name"],
                "scope": row["scope"],
                "path": str(tdir),
                "assets": asset_count,
                "content": content_count,
                "findings": finding_count,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
        return 0

    print(f"Target: {row['name']}")
    print(f"Path: {tdir}")
    print(f"Assets: {asset_count}")
    print(f"Content files: {content_count}")
    print(f"Findings: {finding_count}")
    print(f"Created: {row['created_at']}")
    print(f"Updated: {row['updated_at']}")
    print("Scope:")
    if row["scope"]:
        print(textwrap.indent(row["scope"], "  "))
    else:
        print("  (empty)")
    return 0


def cmd_target_update(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace
) -> int:
    row = _target_row(conn, args.name)
    if args.scope is None and args.scope_file is None:
        raise HackbotError("provide --scope or --scope-file")
    scope = _read_scope(args)
    with conn:
        conn.execute(
            "UPDATE targets SET scope = ?, updated_at = ? WHERE id = ?",
            (scope, now_iso(), row["id"]),
        )
    if args.json:
        print_json({"name": row["name"], "scope": scope})
    else:
        print(f"Updated scope for target '{row['name']}'.")
    return 0


def cmd_findings_list(
    conn: sqlite3.Connection,
    *,
    target_name: str | None,
    page: int,
    limit: int,
    finding_type: str | None,
    status: str | None,
    as_json: bool,
) -> int:
    if page < 1:
        raise HackbotError("--page must be 1 or greater")
    if limit < 1 or limit > 500:
        raise HackbotError("--limit must be between 1 and 500")

    where: list[str] = []
    params: list[Any] = []
    if target_name:
        target = _target_row(conn, target_name)
        where.append("f.target_id = ?")
        params.append(target["id"])
    if finding_type:
        where.append("f.type = ?")
        params.append(finding_type)
    if status:
        where.append("f.status = ?")
        params.append(status)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM findings f{where_sql}", params
    ).fetchone()[0]
    pages = (total + limit - 1) // limit if total else 0
    if total and page > pages:
        raise HackbotError(f"page {page} does not exist; last page is {pages}")

    rows = list(
        conn.execute(
            f"""
            SELECT f.id, f.title, t.name AS target, f.type, f.severity, f.status,
                   f.created_at, f.updated_at
            FROM findings f
            JOIN targets t ON t.id = f.target_id
            {where_sql}
            ORDER BY f.created_at DESC, f.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, (page - 1) * limit),
        ).fetchall()
    )

    if as_json:
        print_json(
            {
                "findings": [dict(row) for row in rows],
                "page": page,
                "pages": pages,
                "total": total,
            }
        )
        return 0

    if not rows:
        if target_name:
            print(f"No findings for target '{target_name}'.")
        else:
            print("No findings.")
        return 0

    print_table(
        ("ID", "TITLE", "TARGET", "TYPE"),
        [(row["id"], row["title"], row["target"], row["type"]) for row in rows],
    )
    if pages > 1:
        print()
        print(
            f"Page {page}/{pages} - {total} finding{'s' if total != 1 else ''}. "
            f"Use --page <n>."
        )
    return 0


def cmd_finding_detail(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace
) -> int:
    row = _resolve_finding(conn, args.finding_id)
    assets = _assets_for_finding(conn, row["id"])
    abs_path = root / row["file_path"]
    github_url = git_sync.github_file_url(root, row["file_path"])

    if args.path:
        if args.json:
            raise HackbotError("--json cannot be combined with --path")
        print(abs_path)
        return 0
    if args.url:
        if args.json:
            raise HackbotError("--json cannot be combined with --url")
        if not github_url:
            raise HackbotError("no GitHub origin remote is configured")
        print(github_url)
        return 0

    body = ""
    if abs_path.exists():
        body = abs_path.read_text(encoding="utf-8", errors="replace")
    attachments: list[str] = []
    attachment_dir = abs_path.with_suffix("")
    if attachment_dir.is_dir():
        attachments = sorted(
            path.relative_to(root).as_posix()
            for path in attachment_dir.rglob("*")
            if path.is_file()
        )

    if args.json:
        print_json(
            {
                "id": row["id"],
                "title": row["title"],
                "target": row["target_name"],
                "type": row["type"],
                "severity": row["severity"],
                "status": row["status"],
                "assets": [asset["value"] for asset in assets],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "path": str(abs_path),
                "github_url": github_url,
                "attachments": attachments,
                "body": body,
            }
        )
        return 0

    print(f"ID: {row['id']}")
    print(f"Title: {row['title']}")
    print(f"Target: {row['target_name']}")
    print(f"Type: {row['type']}")
    print(f"Severity: {row['severity'] or '-'}")
    print(f"Status: {row['status']}")
    print(f"Assets: {', '.join(asset['value'] for asset in assets) or '-'}")
    print(f"Created: {row['created_at']}")
    print(f"Updated: {row['updated_at']}")
    print(f"Local path: {abs_path}")
    print(f"GitHub: {github_url or '(no GitHub remote configured)'}")
    if attachments:
        print("Attachments:")
        for path in attachments:
            print(f"  - {path}")
    print("---")
    if body:
        print(body, end="" if body.endswith("\n") else "\n")
    else:
        print(f"(report file missing: {abs_path})")
    return 0


def cmd_finding_add(root: Path, conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    target = _target_row(conn, args.target)
    title = (args.title or "").strip()
    if not title:
        raise HackbotError("title cannot be empty")
    title = " ".join(title.splitlines())
    finding_id = _next_finding_id(conn)
    file_rel = f"targets/{target['name']}/findings/{finding_id}.md"
    file_abs = root / file_rel
    body = (
        read_text_file(args.body_file)
        if args.body_file
        else FINDING_TEMPLATE.format(title=title)
    )
    if not body.endswith("\n"):
        body += "\n"

    file_abs.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(file_abs, body)
    now = now_iso()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO findings
                    (id, target_id, title, type, severity, status, file_path,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    target["id"],
                    title,
                    args.type,
                    args.severity,
                    args.status,
                    file_rel,
                    now,
                    now,
                ),
            )
            for spec in args.asset:
                asset_id, _, _, _ = _ensure_asset(conn, target["id"], spec)
                conn.execute(
                    "INSERT OR IGNORE INTO finding_assets (finding_id, asset_id) VALUES (?, ?)",
                    (finding_id, asset_id),
                )
    except BaseException:
        file_abs.unlink(missing_ok=True)
        raise

    if args.json:
        print_json(
            {
                "id": finding_id,
                "title": title,
                "target": target["name"],
                "type": args.type,
                "path": str(file_abs),
                "github_url": git_sync.github_file_url(root, file_rel),
            }
        )
    else:
        print(f"Created {finding_id}: {file_abs}")
    return 0


def cmd_finding_update(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace
) -> int:
    row = _resolve_finding(conn, args.finding_id)
    updates: list[str] = []
    params: list[Any] = []
    if args.title is not None:
        title = " ".join(args.title.strip().splitlines())
        if not title:
            raise HackbotError("title cannot be empty")
        updates.append("title = ?")
        params.append(title)
    if args.type is not None:
        updates.append("type = ?")
        params.append(args.type)
    if args.severity is not None:
        updates.append("severity = ?")
        params.append(args.severity)
    if args.status is not None:
        updates.append("status = ?")
        params.append(args.status)

    body_text: str | None = None
    if args.body_file is not None:
        body_text = read_text_file(args.body_file)
        if not body_text.endswith("\n"):
            body_text += "\n"

    replace_assets = args.asset is not None
    if not updates and body_text is None and not replace_assets:
        raise HackbotError("no changes requested")

    abs_path = root / row["file_path"]
    old_body = (
        abs_path.read_text(encoding="utf-8", errors="replace")
        if abs_path.exists()
        else None
    )
    if body_text is not None:
        write_atomic(abs_path, body_text)

    updates.append("updated_at = ?")
    params.append(now_iso())
    params.append(row["id"])

    try:
        with conn:
            conn.execute(
                f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", params
            )
            if replace_assets:
                conn.execute(
                    "DELETE FROM finding_assets WHERE finding_id = ?", (row["id"],)
                )
                for spec in args.asset:
                    asset_id, _, _, _ = _ensure_asset(
                        conn, row["target_id"], spec
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_assets (finding_id, asset_id) VALUES (?, ?)",
                        (row["id"], asset_id),
                    )
    except BaseException:
        if body_text is not None:
            if old_body is None:
                abs_path.unlink(missing_ok=True)
            else:
                write_atomic(abs_path, old_body)
        raise

    if args.json:
        print_json(
            {
                "id": row["id"],
                "path": str(abs_path),
                "github_url": git_sync.github_file_url(root, row["file_path"]),
            }
        )
    else:
        print(f"Updated {row['id']}: {abs_path}")
    return 0


def cmd_asset_add(root: Path, conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    target = _target_row(conn, args.target)
    metadata = parse_json_object(args.meta) if args.meta else None
    source_file = _stored_source_path(root, args.source_file)
    with conn:
        asset_id, _, value, action = _ensure_asset(
            conn,
            target["id"],
            f"{args.kind}:{args.value}",
            status=args.status,
            metadata=metadata,
            source_file=source_file,
        )
    if args.json:
        print_json(
            {
                "id": asset_id,
                "kind": args.kind,
                "value": value,
                "action": action,
            }
        )
    else:
        print(f"{action.capitalize()} asset #{asset_id}: {args.kind} {value}")
    return 0


def cmd_asset_import(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace
) -> int:
    target = _target_row(conn, args.target)
    src = Path(args.file).expanduser()
    if not src.is_file():
        raise HackbotError(f"file not found: {src}")
    src = src.resolve()
    tdir = target_dir(root, target["name"])
    _, source_file = _archive_recon_file(root, tdir, src)

    added = 0
    updated = 0
    with conn:
        if args.format == "httpx":
            for item in _read_httpx(src):
                host = _host_from_httpx(item)
                if not host:
                    continue
                metadata = _httpx_metadata(item)
                status = "live" if item.get("status_code") else "unknown"
                _, action = _upsert_asset(
                    conn,
                    target["id"],
                    args.kind,
                    normalize_asset_value(args.kind, host),
                    status=status,
                    metadata=metadata,
                    source_file=source_file,
                )
                if action == "added":
                    added += 1
                else:
                    updated += 1
        else:
            text = src.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                value = normalize_asset_value(args.kind, line)
                _, action = _upsert_asset(
                    conn,
                    target["id"],
                    args.kind,
                    value,
                    source_file=source_file,
                )
                if action == "added":
                    added += 1
                else:
                    updated += 1

    if args.json:
        print_json(
            {
                "target": target["name"],
                "kind": args.kind,
                "added": added,
                "updated": updated,
                "source_file": source_file,
            }
        )
    else:
        print(
            f"Imported {added + updated} {args.kind} asset"
            f"{'s' if added + updated != 1 else ''} ({added} new, {updated} updated)."
        )
    return 0


def cmd_assets(root: Path, conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    target = _target_row(conn, args.target)
    where = ["target_id = ?"]
    params: list[Any] = [target["id"]]
    if args.kind:
        where.append("kind = ?")
        params.append(args.kind)
    if args.status:
        where.append("status = ?")
        params.append(args.status)
    rows = list(
        conn.execute(
            f"""
            SELECT id, kind, value, status, metadata, source_file, first_seen, last_seen
            FROM assets
            WHERE {' AND '.join(where)}
            ORDER BY kind, value COLLATE NOCASE
            """,
            params,
        ).fetchall()
    )
    if args.json:
        print_json(
            {
                "target": target["name"],
                "assets": [
                    {
                        **dict(row),
                        "metadata": parse_json_text(row["metadata"]),
                    }
                    for row in rows
                ],
            }
        )
        return 0
    if not rows:
        print("No assets.")
        return 0
    print_table(
        ("ID", "KIND", "VALUE", "STATUS"),
        [(row["id"], row["kind"], row["value"], row["status"]) for row in rows],
    )
    return 0


def _find_assets(
    conn: sqlite3.Connection, value: str, target_name: str | None
) -> list[sqlite3.Row]:
    sql = """
        SELECT a.*, t.name AS target_name
        FROM assets a
        JOIN targets t ON t.id = a.target_id
        WHERE a.value = ?
    """
    extra = ""
    params: list[Any] = []
    if target_name:
        extra = " AND t.name = ?"

    kind, raw_value = asset_kind_and_value(value)
    candidates = [raw_value] if raw_value != value else []
    candidates.append(value)
    for candidate in candidates:
        query_params: list[Any] = [candidate]
        if target_name:
            query_params.append(target_name)
        rows = list(conn.execute(sql + extra, query_params).fetchall())
        if rows:
            return rows
    if target_name:
        return rows
    try:
        normalized = normalize_asset_value(kind, raw_value)
    except HackbotError:
        return []
    if normalized in candidates:
        return []
    query_params = [normalized]
    return list(conn.execute(sql, query_params).fetchall())


def cmd_content_list(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace
) -> int:
    assets = _find_assets(conn, args.asset, args.target)
    if not assets:
        raise HackbotError(f"asset '{args.asset}' not found")
    if len(assets) > 1:
        names = ", ".join(asset["target_name"] for asset in assets)
        raise HackbotError(
            f"asset '{args.asset}' exists in multiple targets ({names}); use --target"
        )
    asset = assets[0]
    where = ["c.asset_id = ?"]
    params: list[Any] = [asset["id"]]
    if args.kind:
        where.append("c.kind = ?")
        params.append(args.kind)
    rows = list(
        conn.execute(
            f"""
            SELECT c.*, a.value AS asset, t.name AS target
            FROM content c
            JOIN assets a ON a.id = c.asset_id
            JOIN targets t ON t.id = a.target_id
            WHERE {' AND '.join(where)}
            ORDER BY c.kind, c.path
            """,
            params,
        ).fetchall()
    )
    if args.json:
        print_json(
            {
                "asset": asset["value"],
                "target": asset["target_name"],
                "content": [
                    {
                        **dict(row),
                        "metadata": parse_json_text(row["metadata"]),
                        "absolute_path": str(root / row["path"]),
                    }
                    for row in rows
                ],
            }
        )
        return 0
    if not rows:
        print("No content files.")
        return 0
    print_table(
        ("ID", "KIND", "ITEMS", "SIZE", "PATH"),
        [
            (
                row["id"],
                row["kind"],
                row["item_count"] if row["item_count"] is not None else "-",
                format_bytes(row["size"]),
                row["path"],
            )
            for row in rows
        ],
    )
    return 0


def _content_metadata(path: Path, fmt: str, kind: str, meta: dict[str, Any]) -> dict[str, Any]:
    if fmt == "json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            if "commandline" in data:
                meta.setdefault("commandline", data["commandline"])
            if "time" in data:
                meta.setdefault("run_at", data["time"])
    if kind == "secrets":
        meta.setdefault("redacted", True)
    return meta


def cmd_content_register(
    root: Path, conn: sqlite3.Connection, args: argparse.Namespace, *, copy: bool
) -> int:
    target = _target_row(conn, args.target)
    tdir = target_dir(root, target["name"])
    kind, raw_value = asset_kind_and_value(args.asset)
    value = normalize_asset_value(kind, raw_value)

    src = Path(args.file).expanduser()
    if not src.is_file():
        raise HackbotError(f"file not found: {src}")
    src = src.resolve()

    if copy:
        if args.name is not None:
            name = Path(args.name).name
            if not name or name in {".", ".."}:
                raise HackbotError("--name must be a filename")
        else:
            name = src.name
        dest_dir = tdir / "content" / safe_asset_dir(value) / CONTENT_KIND_DIRS[args.kind]
        dest = dest_dir / name
        if dest.exists() and dest.resolve() != src:
            same = sha256_file(dest) == sha256_file(src)
            if same:
                pass
            elif args.force:
                copy_atomic(src, dest)
            else:
                raise HackbotError(
                    f"destination already exists: {dest}; use --name or --force"
                )
        else:
            copy_atomic(src, dest)
    else:
        if args.name is not None:
            raise HackbotError("--name is only valid with content import")
        if args.force:
            raise HackbotError("--force is only valid with content import")
        ensure_within(src, tdir)
        dest = src

    file_rel = relative_to_root(dest, root)
    size = dest.stat().st_size
    digest = sha256_file(dest)
    fmt = args.file_format or detect_format(dest)
    items = count_items(dest, fmt)
    metadata = _content_metadata(dest, fmt, args.kind, parse_json_object(args.meta))

    now = now_iso()
    with conn:
        asset_id, _, resolved_value, _ = _ensure_asset(conn, target["id"], args.asset)
        existing = conn.execute(
            "SELECT id FROM content WHERE asset_id = ? AND path = ?",
            (asset_id, file_rel),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """
                UPDATE content
                SET kind = ?, source_url = ?, tool = ?, format = ?, item_count = ?,
                    size = ?, sha256 = ?, metadata = ?, last_seen = ?
                WHERE id = ?
                """,
                (
                    args.kind,
                    args.source_url,
                    args.tool,
                    fmt,
                    items,
                    size,
                    digest,
                    json_dumps(metadata),
                    now,
                    existing["id"],
                ),
            )
            content_id = int(existing["id"])
            action = "updated"
        else:
            cursor = conn.execute(
                """
                INSERT INTO content
                    (asset_id, kind, path, source_url, tool, format, item_count,
                     size, sha256, metadata, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asset_id,
                    args.kind,
                    file_rel,
                    args.source_url,
                    args.tool,
                    fmt,
                    items,
                    size,
                    digest,
                    json_dumps(metadata),
                    now,
                    now,
                ),
            )
            content_id = int(cursor.lastrowid)
            action = "imported" if copy else "registered"

    if args.kind == "secrets" and "secrets" not in dest.parts:
        print(
            "warning: secret file is outside a secrets/ directory; git sync may commit it",
            file=sys.stderr,
        )

    if args.json:
        print_json(
            {
                "id": content_id,
                "asset": resolved_value,
                "kind": args.kind,
                "path": str(dest),
                "relative_path": file_rel,
                "sha256": digest,
                "size": size,
                "items": items,
                "format": fmt,
                "action": action,
            }
        )
    else:
        print(f"{action.capitalize()} content #{content_id}: {file_rel}")
    return 0


def cmd_sync(root: Path, args: argparse.Namespace) -> int:
    return git_sync.sync(root, install_cron_entry=args.install_cron)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        root_arg, argv = _extract_root(raw_argv)
        root = resolve_root(root_arg)
    except HackbotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not argv:
        parser.print_help()
        return 0

    if argv[0].startswith("-"):
        try:
            parser.parse_args(argv)
        except SystemExit as exc:
            return int(exc.code or 0)
        parser.print_help()
        return 0

    if argv[0] == "content":
        if len(argv) == 1:
            argv = ["content", "--help"]
        elif argv[1] not in {"list", "add", "import", "-h", "--help"}:
            argv = ["content", "list", *argv[1:]]
    elif argv[0] not in KNOWN_COMMANDS:
        if len(argv) >= 2 and argv[1] == "findings":
            argv = ["findings", "--target", argv[0], *argv[2:]]
        else:
            print(f"error: unknown command '{argv[0]}'", file=sys.stderr)
            print("Run 'hackbot help' for usage.", file=sys.stderr)
            return 2

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    try:
        if args.command in {None, "help"}:
            parser.print_help()
            return 0
        if args.command == "init":
            return cmd_init(root, args)
        if args.command == "sync":
            return cmd_sync(root, args)

        if not (root / ".hackbot").exists():
            raise HackbotError("data root is not initialized; run 'hackbot init' first")
        conn = dbmod.connect(root)
        try:
            if args.command == "targets":
                return cmd_targets(root, conn)
            if args.command == "target":
                if args.target_command == "add":
                    return cmd_target_add(root, conn, args)
                if args.target_command == "show":
                    return cmd_target_show(root, conn, args)
                if args.target_command == "update":
                    return cmd_target_update(root, conn, args)
            if args.command == "findings":
                if args.finding_id:
                    if (
                        args.target
                        or args.type
                        or args.status
                        or args.page != 1
                        or args.limit != 20
                    ):
                        raise HackbotError(
                            "list filters cannot be used with a finding id"
                        )
                    return cmd_finding_detail(root, conn, args)
                if args.path or args.url:
                    raise HackbotError("--path and --url require a finding id")
                return cmd_findings_list(
                    conn,
                    target_name=args.target,
                    page=args.page,
                    limit=args.limit,
                    finding_type=args.type,
                    status=args.status,
                    as_json=args.json,
                )
            if args.command == "finding":
                if args.finding_command == "add":
                    return cmd_finding_add(root, conn, args)
                if args.finding_command == "update":
                    return cmd_finding_update(root, conn, args)
            if args.command == "asset":
                if args.asset_command == "add":
                    return cmd_asset_add(root, conn, args)
                if args.asset_command == "import":
                    return cmd_asset_import(root, conn, args)
            if args.command == "assets":
                return cmd_assets(root, conn, args)
            if args.command == "content":
                if args.content_command == "list":
                    return cmd_content_list(root, conn, args)
                if args.content_command == "add":
                    return cmd_content_register(root, conn, args, copy=False)
                if args.content_command == "import":
                    return cmd_content_register(root, conn, args, copy=True)
        finally:
            conn.close()
    except HackbotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"error: database error: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0
