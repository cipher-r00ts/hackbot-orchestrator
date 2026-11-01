from __future__ import annotations

import csv
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

ASSET_KINDS = (
    "domain",
    "subdomain",
    "ip",
    "android",
    "ios",
    "desktop",
    "binary",
    "other",
)

CONTENT_KINDS = (
    "urls",
    "endpoints",
    "params",
    "js",
    "secrets",
    "responses",
    "screenshots",
    "other",
)

CONTENT_KIND_DIRS = {
    "urls": "urls",
    "endpoints": "endpoints",
    "params": "params",
    "js": "js",
    "secrets": "secrets",
    "responses": "responses",
    "screenshots": "screenshots",
    "other": "misc",
}

FINDING_TYPES = ("gadget", "lead", "finding")

RESERVED_TARGET_NAMES = {
    "help",
    "targets",
    "target",
    "findings",
    "finding",
    "asset",
    "assets",
    "content",
    "content-add",
    "content-import",
    "sync",
    "init",
    "target-findings",
}

_TARGET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class HackbotError(Exception):
    """User-facing error."""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_root() -> Path:
    return resolve_root(None)


def resolve_root(value: str | None = None) -> Path:
    raw = value or os.environ.get("HACKBOT_ROOT") or "~/BugBounty"
    return Path(raw).expanduser().resolve()


def validate_target_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise HackbotError("target name cannot be empty")
    if name.lower() in RESERVED_TARGET_NAMES:
        raise HackbotError(f"'{name}' is reserved; choose another target name")
    if not _TARGET_NAME_RE.match(name):
        raise HackbotError(
            "target name must start with a letter or digit and contain only "
            "letters, digits, dots, underscores, and hyphens"
        )
    return name


def safe_asset_dir(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "asset"
    return cleaned[:120]


def target_dir(root: Path, name: str) -> Path:
    return Path(root) / "targets" / name


def target_content_dir(root: Path, name: str, asset: str) -> Path:
    return target_dir(root, name) / "content" / safe_asset_dir(asset)


def relative_to_root(path: Path, root: Path) -> str:
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()


def ensure_within(path: Path, base: Path) -> Path:
    resolved = Path(path).resolve()
    base = Path(base).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise HackbotError(f"{path} is outside {base}") from exc
    return resolved


def write_atomic(path: Path, data: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def copy_atomic(src: Path, dest: Path) -> None:
    src = Path(src)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() == dest.resolve():
        return
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", dir=dest.parent)
    os.close(fd)
    try:
        shutil.copy2(src, tmp_name)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def read_text_file(value: str) -> str:
    if value == "-":
        return sys.stdin.read()
    path = Path(value).expanduser()
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HackbotError(f"cannot read {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_format(path: Path) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".txt": "txt",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "jsonl",
        ".js": "js",
        ".mjs": "js",
        ".cjs": "js",
        ".html": "html",
        ".htm": "html",
        ".csv": "csv",
        ".xml": "xml",
        ".yaml": "yaml",
        ".yml": "yaml",
    }.get(suffix, "other")


def count_items(path: Path, fmt: str) -> int:
    """Best-effort number of records in a recon file.

    This is only a display/search aid. The file remains the source of truth.
    """
    try:
        if fmt == "json":
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in ("results", "items", "data"):
                    value = data.get(key)
                    if isinstance(value, list):
                        return len(value)
            return 1
        if fmt == "jsonl":
            count = 0
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    count += 1
            return count
        if fmt == "csv":
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.reader(handle)
                return max(0, sum(1 for _ in reader) - 1)
        if fmt in {"txt", "other", "yaml", "xml"}:
            count = 0
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.strip():
                        count += 1
            return count
    except OSError:
        return 0
    return 1


def parse_json_object(text: str | None, what: str = "metadata") -> dict[str, Any]:
    if text is None or text.strip() == "":
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HackbotError(f"{what} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise HackbotError(f"{what} must be a JSON object")
    return value


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_json_text(text: str | None) -> Any:
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def normalize_asset_value(kind: str, value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise HackbotError("asset value cannot be empty")

    if kind in {"domain", "subdomain"}:
        if "://" in value:
            parsed = urlsplit(value)
            value = parsed.hostname or value
        value = value.split("/", 1)[0].rstrip(".").lower()
        # Strip a single host:port form. Leave IPv6 literals alone.
        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                value = host
    return value


def asset_kind_and_value(spec: str) -> tuple[str, str]:
    spec = (spec or "").strip()
    if ":" in spec:
        prefix, rest = spec.split(":", 1)
        if prefix in ASSET_KINDS and rest:
            return prefix, rest
    try:
        import ipaddress

        ipaddress.ip_address(spec)
        return "ip", spec
    except ValueError:
        return "subdomain", spec


def format_bytes(size: int | None) -> str:
    if size is None:
        return "-"
    size = int(size)
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f}K"
    return f"{size / (1024 * 1024):.1f}M"


def truncate(text: str, width: int) -> str:
    text = str(text)
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


@contextmanager
def file_lock(path: Path, blocking: bool = True) -> Iterator[bool]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as handle:
        flags = fcntl.LOCK_EX
        if not blocking:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(handle.fileno(), flags)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def looks_like_http_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")
