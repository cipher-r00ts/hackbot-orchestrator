# hackbot

Filesystem-first bug bounty manager. Targets, findings, and recon output live in
a Git-backed directory. SQLite indexes targets, assets, content files, and
findings so an agent can query them quickly, but the files remain the source of
truth.

No dashboard, no web UI, no secret manager. Just directories, SQLite, and Git.

## Install

```bash
cd /home/cipher/hackbot
pipx install --editable .
# or: python3 -m pip install --user --editable .
```

Verify:

```bash
hackbot --help
```

## Initialize the data root

The default data root is `~/BugBounty`.

```bash
hackbot init
```

Override it when needed:

```bash
HACKBOT_ROOT=/path/to/data hackbot init
# or
hackbot --root /path/to/data init
```

`hackbot init` creates the directory layout, the SQLite database, a text
snapshot, `.gitignore`, and a local Git repository. It does not commit anything
or touch unmanaged directories.

## Layout

```text
~/BugBounty/
├── .gitignore
├── .hackbot/
│   ├── hackbot.db          # live SQLite DB, gitignored
│   └── hackbot.sql         # deterministic text snapshot, committed
└── targets/
    └── acme/
        ├── findings/
        │   ├── F-0001.md
        │   └── F-0001/     # optional scripts/attachments
        ├── content/
        │   └── api.acme.com/
        │       ├── endpoints/
        │       ├── js/
        │       ├── secrets/    # gitignored
        │       └── ...
        └── artifacts/
            ├── recon/
            ├── analysis/
            └── reports/
```

Artifacts are plain files. Raw recon runs belong in `artifacts/recon/`.
Content files are indexed in SQLite at file level and remain readable with
`rg`, `jq`, `cat`, etc.

## Core commands

```bash
hackbot                     # help
hackbot help
hackbot targets             # target names, one per line
hackbot findings            # paginated table
hackbot findings F-0001     # finding detail + local path + GitHub URL
hackbot acme findings       # findings for one target
```

`hackbot findings` supports:

```bash
--page N
--limit N
--target NAME
--type gadget|lead|finding
--status STATUS
--json
```

To get only the path or GitHub URL of a finding:

```bash
hackbot findings F-0001 --path
hackbot findings F-0001 --url
```

The GitHub URL is built from the `origin` remote and the current branch. It
works for `git@github.com:owner/repo.git` and
`https://github.com/owner/repo.git`.

## Target management

```bash
hackbot target add acme --scope-file scope.txt
hackbot target add acme --scope "api.acme.com
*.acme.com"
hackbot target add acme --scope -        # read scope from stdin
hackbot target show acme
hackbot target update acme --scope-file new-scope.txt
```

`target add` creates:

```text
targets/<name>/findings/
targets/<name>/content/
targets/<name>/artifacts/{recon,analysis,reports}/
```

Scope is stored as raw text on the target. It is not parsed.

## Findings

Finding metadata lives in SQLite. The report body lives in
`targets/<target>/findings/F-XXXX.md`.

```bash
hackbot finding add acme \
  --title "IDOR in /v1/users" \
  --type finding \
  --severity high \
  --status open \
  --asset api.acme.com \
  --body-file report.md

hackbot finding update F-0001 --status triaged
hackbot finding update F-0001 --body-file updated-report.md
hackbot finding update F-0001 --asset android:com.acme.app
```

Types are `gadget`, `lead`, and `finding`.

If `--asset` names an unknown asset, it is created. A plain value becomes a
subdomain; use `kind:value` for anything else, for example
`android:com.acme.app`.

If a finding needs attachments, create `targets/<target>/findings/F-XXXX/` and
put them there. `hackbot findings F-XXXX` lists them.

## Assets

```bash
hackbot asset add acme subdomain api.acme.com --status live
hackbot asset add acme android com.acme.app --meta '{"store":"play"}'
hackbot asset import acme subdomain subdomains.txt
hackbot asset import acme subdomain httpx.jsonl --format httpx
hackbot assets acme
hackbot assets acme --kind subdomain --status live
```

Asset kinds: `domain`, `subdomain`, `ip`, `android`, `ios`, `desktop`,
`binary`, `other`.

Importing an external recon file archives it under
`targets/<target>/artifacts/recon/`.

`--format httpx` accepts JSONL or a JSON array and stores status, title, tech,
ports, and related fields in the asset metadata.

## Content files

Content is indexed at file level. The actual file stays in
`targets/<target>/content/<asset>/`.

```bash
hackbot content import acme api.acme.com endpoints ffuf.json --tool ffuf
hackbot content import acme api.acme.com js app.js \
  --url https://api.acme.com/app.js
hackbot content import acme api.acme.com secrets secrets.txt
hackbot content add acme api.acme.com other note.txt
hackbot content api.acme.com
```

`content import` copies an external file into the content directory.
`content add` registers a file that is already inside the target directory.

Content kinds and default directories:

| kind | directory |
|---|---|
| `urls` | `urls/` |
| `endpoints` | `endpoints/` |
| `params` | `params/` |
| `js` | `js/` |
| `secrets` | `secrets/` |
| `responses` | `responses/` |
| `screenshots` | `screenshots/` |
| `other` | `misc/` |

For JSON output, use `--json`:

```bash
hackbot assets acme --json
hackbot content api.acme.com --json
hackbot target show acme --json
hackbot findings --json
hackbot findings F-0001 --json
```

## Secrets

Raw secret files under a `secrets/` directory are gitignored. The database
stores the file path, hash, size, and redacted metadata, not the secret value.

Do not paste live secrets into finding report bodies that will be committed.
Keep raw evidence under `secrets/` and reference it from the report.

## Git sync

```bash
hackbot sync
hackbot sync --install-cron
```

`sync` does the following:

1. Dumps SQLite to `.hackbot/hackbot.sql`.
2. Stages `.gitignore`, the SQL snapshot, and only targets present in the
   database.
3. Commits changes locally.
4. If an `origin` remote exists, fetches, rebases, and pushes.
5. Aborts on a Git conflict instead of guessing.

Unmanaged directories under `targets/` are never staged. This is intentional:
old or experimental data can coexist in the same directory without being
committed.

`--install-cron` installs a cron entry that runs sync every 15 minutes:

```cron
*/15 * * * * HACKBOT_ROOT=/home/cipher/BugBounty ... -m hackbot sync >> .../.hackbot/sync.log 2>&1
```

The live `hackbot.db` is not committed. On a fresh clone, the first hackbot
command restores it from `.hackbot/hackbot.sql`.

## Design notes

- Content is file-level, not line-level. SQLite tells you which file to inspect;
  use `rg`, `jq`, or the recon tool of your choice on the file.
- `hackbot` does not run recon tools. It only stores, imports, and indexes their
  output.
- There are no delete commands yet. Destructive changes are manual.
- SQLite is a single-writer index. The tool is intended for one active machine
  at a time.
- Project code lives in this repository. Bug bounty data lives in
  `~/BugBounty` and is versioned separately.
