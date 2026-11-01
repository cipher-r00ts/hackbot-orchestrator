from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class HackbotCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hackbot-test-")
        self.root = Path(self.tmp.name) / "data"
        self.env = os.environ.copy()
        self.env["HACKBOT_ROOT"] = str(self.root)
        self.env["PYTHONPATH"] = str(REPO_ROOT)
        self.env["GIT_AUTHOR_NAME"] = "hackbot tests"
        self.env["GIT_AUTHOR_EMAIL"] = "hackbot@example.test"
        self.env["GIT_COMMITTER_NAME"] = "hackbot tests"
        self.env["GIT_COMMITTER_EMAIL"] = "hackbot@example.test"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(
        self,
        *args: str,
        input_text: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "hackbot", *args],
            cwd=REPO_ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            input=input_text,
        )
        if check and result.returncode != 0:
            self.fail(
                f"command failed ({result.returncode}): hackbot {' '.join(args)}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def init(self) -> None:
        self.run_cli("init")

    def add_target(self, name: str = "acme", scope: str = "") -> None:
        args = ["target", "add", name]
        if scope:
            args.extend(["--scope", scope])
        self.run_cli(*args)

    def test_init_targets_and_scope(self) -> None:
        self.init()
        self.assertTrue((self.root / ".git").is_dir())
        self.assertTrue((self.root / ".hackbot" / "hackbot.db").is_file())
        self.assertTrue((self.root / ".hackbot" / "hackbot.sql").is_file())
        self.assertTrue((self.root / "targets").is_dir())
        gitignore = (self.root / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".hackbot/hackbot.db", gitignore)

        empty = self.run_cli("targets")
        self.assertEqual(empty.stdout, "")
        self.assertIn("No targets", empty.stderr)

        self.add_target("acme", "api.acme.com\n*.acme.com")
        self.assertEqual(self.run_cli("targets").stdout, "acme\n")
        target_dir = self.root / "targets" / "acme"
        for rel in (
            "findings",
            "content",
            "artifacts/recon",
            "artifacts/analysis",
            "artifacts/reports",
        ):
            self.assertTrue((target_dir / rel).is_dir(), rel)

        shown = self.run_cli("target", "show", "acme")
        self.assertIn("Target: acme", shown.stdout)
        self.assertIn("api.acme.com", shown.stdout)
        self.assertIn("*.acme.com", shown.stdout)

        self.run_cli("target", "update", "acme", "--scope", "new.example.com")
        shown = self.run_cli("target", "show", "acme", "--json")
        self.assertIn('"scope": "new.example.com"', shown.stdout)

    def test_findings_lifecycle_and_pagination(self) -> None:
        self.init()
        self.add_target()
        body = "# Report\n\nDetails here.\n"
        body_path = Path(self.tmp.name) / "report.md"
        body_path.write_text(body, encoding="utf-8")

        self.run_cli(
            "finding",
            "add",
            "acme",
            "--title",
            "IDOR in users endpoint",
            "--type",
            "finding",
            "--severity",
            "high",
            "--asset",
            "api.acme.com",
            "--body-file",
            str(body_path),
        )
        finding_path = self.root / "targets" / "acme" / "findings" / "F-0001.md"
        self.assertEqual(finding_path.read_text(encoding="utf-8"), body)

        listing = self.run_cli("findings")
        self.assertIn("F-0001", listing.stdout)
        self.assertIn("IDOR in users endpoint", listing.stdout)
        self.assertIn("acme", listing.stdout)
        self.assertIn("finding", listing.stdout)

        by_target = self.run_cli("acme", "findings")
        self.assertIn("F-0001", by_target.stdout)

        path_only = self.run_cli("findings", "F-0001", "--path")
        self.assertEqual(Path(path_only.stdout.strip()), finding_path.resolve())

        detail = self.run_cli("findings", "F-0001")
        self.assertIn("IDOR in users endpoint", detail.stdout)
        self.assertIn("Local path:", detail.stdout)
        self.assertIn(str(finding_path), detail.stdout)
        self.assertIn("Details here.", detail.stdout)
        self.assertIn("GitHub: (no GitHub remote configured)", detail.stdout)

        self.run_cli("finding", "update", "F-0001", "--status", "triaged")
        detail = self.run_cli("findings", "F-0001", "--json")
        self.assertIn('"status": "triaged"', detail.stdout)

        for number in range(2, 24):
            self.run_cli(
                "finding",
                "add",
                "acme",
                "--title",
                f"Test finding {number}",
                "--type",
                "lead",
            )
        page_two = self.run_cli("findings", "--limit", "5", "--page", "2")
        self.assertIn("Page 2/5", page_two.stdout)
        self.assertIn("F-0018", page_two.stdout)

    def test_assets_and_content(self) -> None:
        self.init()
        self.add_target()

        self.run_cli(
            "asset", "add", "acme", "android", "com.acme.app",
            "--status", "active", "--meta", '{"store":"play"}',
        )
        httpx = Path(self.tmp.name) / "httpx.jsonl"
        httpx.write_text(
            '{"url":"https://api.acme.com","status_code":200,"title":"API","tech":["nginx"]}\n'
            '{"url":"https://app.acme.com","status_code":403,"title":"Denied"}\n',
            encoding="utf-8",
        )
        imported = self.run_cli(
            "asset", "import", "acme", "subdomain", str(httpx), "--format", "httpx"
        )
        self.assertIn("2 new", imported.stdout)
        assets = self.run_cli("assets", "acme", "--json")
        self.assertIn('"value": "api.acme.com"', assets.stdout)
        self.assertIn('"status_code": 200', assets.stdout)
        self.assertTrue(
            (self.root / "targets" / "acme" / "artifacts" / "recon" / "httpx.jsonl").is_file()
        )

        android_urls = Path(self.tmp.name) / "android-urls.txt"
        android_urls.write_text("com.acme.app://endpoint\n", encoding="utf-8")
        self.run_cli(
            "content", "import", "acme", "com.acme.app", "urls", str(android_urls)
        )
        assets = self.run_cli("assets", "acme", "--json")
        self.assertEqual(assets.stdout.count('"value": "com.acme.app"'), 1)
        android_content = self.run_cli("content", "com.acme.app")
        self.assertIn("android-urls.txt", android_content.stdout)

        urls = Path(self.tmp.name) / "urls.txt"
        urls.write_text("https://api.acme.com/v1/users?id=1\n/api/v1/orders\n", encoding="utf-8")
        content = self.run_cli(
            "content", "import", "acme", "api.acme.com", "endpoints", str(urls),
            "--tool", "ffuf",
        )
        self.assertIn("Imported content", content.stdout)
        stored = (
            self.root
            / "targets"
            / "acme"
            / "content"
            / "api.acme.com"
            / "endpoints"
            / "urls.txt"
        )
        self.assertTrue(stored.is_file())
        listed = self.run_cli("content", "api.acme.com", "--json")
        self.assertIn('"kind": "endpoints"', listed.stdout)
        self.assertIn('"tool": "ffuf"', listed.stdout)
        self.assertIn('"item_count": 2', listed.stdout)

        js = Path(self.tmp.name) / "app.js"
        js.write_text("const API = 'x';\n", encoding="utf-8")
        self.run_cli(
            "content", "import", "acme", "api.acme.com", "js", str(js),
            "--url", "https://api.acme.com/app.js",
        )
        self.assertTrue(
            (
                self.root
                / "targets"
                / "acme"
                / "content"
                / "api.acme.com"
                / "js"
                / "app.js"
            ).is_file()
        )

        secret = Path(self.tmp.name) / "secret.txt"
        secret.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        self.run_cli("content", "import", "acme", "api.acme.com", "secrets", str(secret))
        secret_path = (
            self.root
            / "targets"
            / "acme"
            / "content"
            / "api.acme.com"
            / "secrets"
            / "secret.txt"
        )
        self.assertTrue(secret_path.is_file())
        ignored = subprocess.run(
            ["git", "-C", str(self.root), "check-ignore", "-q", str(secret_path)],
            check=False,
        )
        self.assertEqual(ignored.returncode, 0)

        self.run_cli("sync")
        dump = (self.root / ".hackbot" / "hackbot.sql").read_text(encoding="utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", dump)

        manual = (
            self.root
            / "targets"
            / "acme"
            / "content"
            / "api.acme.com"
            / "note.txt"
        )
        manual.write_text("manual note\n", encoding="utf-8")
        registered = self.run_cli(
            "content", "add", "acme", "api.acme.com", "other", str(manual)
        )
        self.assertIn("Registered content", registered.stdout)

    def test_sync_commit_and_restore(self) -> None:
        self.init()
        self.add_target()
        legacy = self.root / "targets" / "legacy"
        legacy.mkdir(parents=True)
        (legacy / "keep.txt").write_text("old data\n", encoding="utf-8")
        self.run_cli(
            "finding", "add", "acme", "--title", "Restore me", "--type", "gadget"
        )
        synced = self.run_cli("sync")
        self.assertIn("Committed", synced.stdout)
        self.assertIn("No origin remote", synced.stdout)

        tracked = subprocess.run(
            ["git", "-C", str(self.root), "ls-files"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn(".hackbot/hackbot.sql", tracked)
        self.assertNotIn(".hackbot/hackbot.db", tracked)
        self.assertNotIn("targets/legacy/keep.txt", tracked)
        self.assertIn("targets/acme/findings/F-0001.md", tracked)

        (self.root / ".hackbot" / "hackbot.db").unlink()
        (self.root / ".hackbot" / "hackbot.db-wal").unlink(missing_ok=True)
        (self.root / ".hackbot" / "hackbot.db-shm").unlink(missing_ok=True)

        self.assertEqual(self.run_cli("targets").stdout, "acme\n")
        listing = self.run_cli("findings")
        self.assertIn("F-0001", listing.stdout)
        self.assertIn("Restore me", listing.stdout)

    def test_github_url(self) -> None:
        self.init()
        self.add_target()
        self.run_cli(
            "finding", "add", "acme", "--title", "URL me", "--type", "finding"
        )
        subprocess.run(
            ["git", "-C", str(self.root), "remote", "add", "origin",
             "git@github.com:owner/repo.git"],
            check=True,
        )
        url = self.run_cli("findings", "F-0001", "--url").stdout.strip()
        self.assertEqual(
            url,
            "https://github.com/owner/repo/blob/main/targets/acme/findings/F-0001.md",
        )

    def test_errors(self) -> None:
        uninitialized = self.run_cli("targets", check=False)
        self.assertEqual(uninitialized.returncode, 1)
        self.assertIn("not initialized", uninitialized.stderr)

        self.init()
        self.add_target()
        duplicate = self.run_cli("target", "add", "acme", check=False)
        self.assertEqual(duplicate.returncode, 1)
        self.assertIn("already exists", duplicate.stderr)

        reserved = self.run_cli("target", "add", "findings", check=False)
        self.assertEqual(reserved.returncode, 1)
        self.assertIn("reserved", reserved.stderr)

        bad_name = self.run_cli("target", "add", "bad name", check=False)
        self.assertEqual(bad_name.returncode, 1)

        missing_asset = self.run_cli("content", "missing.example", check=False)
        self.assertEqual(missing_asset.returncode, 1)
        self.assertIn("not found", missing_asset.stderr)

        missing_finding = self.run_cli("findings", "F-9999", check=False)
        self.assertEqual(missing_finding.returncode, 1)

    def test_scope_from_stdin(self) -> None:
        self.init()
        self.run_cli(
            "target", "add", "stdin-target", "--scope", "-",
            input_text="scope line one\nscope line two\n",
        )
        shown = self.run_cli("target", "show", "stdin-target")
        self.assertIn("scope line one", shown.stdout)
        self.assertIn("scope line two", shown.stdout)


if __name__ == "__main__":
    unittest.main()
