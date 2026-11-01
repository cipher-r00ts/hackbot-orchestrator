from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

from . import db as dbmod
from .util import HackbotError, file_lock, now_iso

_GITHUB_REMOTE_PATTERNS = (
    re.compile(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
    re.compile(r"^ssh://git@github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
    re.compile(r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
)


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            capture_output=True,
            check=check,
        )
    except FileNotFoundError as exc:
        raise HackbotError("git is not installed") from exc
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or "").strip()
        raise HackbotError(f"git {' '.join(args)} failed: {message}") from exc


def _git_ok(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HackbotError("git is not installed") from exc


def remote_url(root: Path) -> str | None:
    result = _git_ok(root, "remote", "get-url", "origin")
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def current_branch(root: Path) -> str:
    result = _git_ok(root, "symbolic-ref", "--short", "HEAD")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    result = _git_ok(root, "rev-parse", "--abbrev-ref", "HEAD")
    if result.returncode == 0:
        value = result.stdout.strip()
        if value and value != "HEAD":
            return value
    return "main"


def parse_github_remote(url: str) -> tuple[str, str] | None:
    for pattern in _GITHUB_REMOTE_PATTERNS:
        match = pattern.match(url.strip())
        if match:
            repo = match.group("repo")
            if repo.endswith(".git"):
                repo = repo[:-4]
            return match.group("owner"), repo
    return None


def github_file_url(root: Path, relative_path: str) -> str | None:
    url = remote_url(root)
    if not url:
        return None
    parsed = parse_github_remote(url)
    if not parsed:
        return None
    owner, repo = parsed
    branch = current_branch(root)
    branch_q = quote(branch, safe="/")
    path_q = quote(Path(relative_path).as_posix(), safe="/")
    return f"https://github.com/{owner}/{repo}/blob/{branch_q}/{path_q}"


def _cron_command() -> str:
    script = shutil.which("hackbot")
    if script:
        return shlex.quote(script)
    package_parent = Path(__file__).resolve().parent.parent
    return (
        f"PYTHONPATH={shlex.quote(str(package_parent))} "
        f"{shlex.quote(sys.executable)} -m hackbot"
    )


def _cron_line(root: Path) -> str:
    log_path = Path(root) / ".hackbot" / "sync.log"
    return (
        "*/15 * * * * "
        f"HACKBOT_ROOT={shlex.quote(str(root))} "
        f"{_cron_command()} sync "
        f">> {shlex.quote(str(log_path))} 2>&1"
    )


def install_cron(root: Path) -> None:
    if shutil.which("crontab") is None:
        raise HackbotError("crontab is not installed")
    line = _cron_line(root)
    current = subprocess.run(
        ["crontab", "-l"], text=True, capture_output=True, check=False
    )
    existing = current.stdout if current.returncode == 0 else ""
    if line in existing.splitlines():
        print("Cron entry already installed.")
        return
    new_content = existing.rstrip("\n")
    if new_content:
        new_content += "\n"
    new_content += line + "\n"
    try:
        subprocess.run(
            ["crontab", "-"], input=new_content, text=True, check=True, capture_output=True
        )
    except subprocess.CalledProcessError as exc:
        raise HackbotError(f"could not install cron entry: {exc.stderr}") from exc
    print("Installed cron entry (every 15 minutes).")


def _stage_managed(root: Path, target_names: list[str]) -> None:
    """Stage only files managed by hackbot.

    Unmanaged directories under targets/ (for example old/experimental data)
    are deliberately left untracked.
    """
    paths = [".gitignore", ".hackbot/hackbot.sql"]
    _git_ok(root, "add", "-A", "--", *paths)
    for name in target_names:
        relative = f"targets/{name}"
        if (root / relative).exists():
            _git_ok(root, "add", "-A", "--", relative)
        else:
            _git_ok(root, "rm", "-r", "--cached", "--ignore-unmatch", "--", relative)


def sync(root: Path, *, install_cron_entry: bool = False) -> int:
    root = Path(root)
    if not (root / ".hackbot").exists():
        raise HackbotError("data root is not initialized; run 'hackbot init' first")

    lock_path = root / ".hackbot" / "sync.lock"
    with file_lock(lock_path, blocking=False) as acquired:
        if not acquired:
            print("Another hackbot sync is already running; skipping.")
            return 0

        if install_cron_entry:
            install_cron(root)

        conn = dbmod.connect(root)
        try:
            dbmod.dump_database(conn, dbmod.dump_path(root))
            target_names = [
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM targets ORDER BY name COLLATE NOCASE"
                ).fetchall()
            ]
        finally:
            conn.close()

        if not (root / ".git").exists():
            raise HackbotError("data root is not a git repository; run 'hackbot init'")

        _stage_managed(root, target_names)
        staged = _git_ok(root, "diff", "--cached", "--quiet")
        changed = staged.returncode != 0
        if changed:
            message = f"hackbot sync: {now_iso()}"
            result = _git_ok(root, "commit", "-m", message)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise HackbotError(f"git commit failed: {detail}")
            print(f"Committed: {message}")
        else:
            print("No file changes to commit.")

        remote = remote_url(root)
        if not remote:
            print("No origin remote configured; changes are committed locally only.")
            return 0

        fetch = _git_ok(root, "fetch", "origin")
        if fetch.returncode != 0:
            detail = (fetch.stderr or fetch.stdout or "").strip()
            raise HackbotError(f"git fetch failed: {detail}")

        branch = current_branch(root)
        remote_branch = _git_ok(root, "rev-parse", "--verify", f"origin/{branch}")
        if remote_branch.returncode == 0:
            rebase = _git_ok(root, "rebase", f"origin/{branch}")
            if rebase.returncode != 0:
                _git_ok(root, "rebase", "--abort")
                detail = (rebase.stderr or rebase.stdout or "").strip()
                raise HackbotError(
                    "git rebase failed; resolve the conflict manually. "
                    f"Details: {detail}"
                )

        push = _git_ok(root, "push", "-u", "origin", branch)
        if push.returncode != 0:
            detail = (push.stderr or push.stdout or "").strip()
            raise HackbotError(f"git push failed: {detail}")
        print(f"Pushed to origin/{branch}.")
        return 0
