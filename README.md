# leak-check

Keys and client data end up in places you did not plan: a `.env` file Claude can read, a key you pasted into a chat, a tool result that echoed a password. Claude Code keeps session transcripts on disk, so these stay around.

## What it does

- Scans a project folder and a transcripts folder for known key shapes, private key headers, JWTs, secret-looking `.env` lines, emails, phone numbers and names from a file you supply.
- Prints every match masked: first 4 characters + `****`. It never prints a full value.
- Lists which secret-looking files Claude can read, and whether a `permissions.deny` rule covers each.
- Writes `proposed-settings.json` (deny rules plus a PreToolUse hook entry) and `proposed-hook.sh`. These are proposals. Nothing is applied.
- `--scrub --apply` rewrites transcripts, replacing secrets with `[REDACTED]`, after copying each changed file to `.bak`. Without `--apply` it prints a plan.

## Install

```bash
git clone https://github.com/umerdarazkha-debug/leak-check ~/.claude/skills/leak-check
```

Needs `uv` and `python3` (the proposed hook uses `python3` to read its input). Standard library only.

## Use

Ask Claude: "run a leak check on this project". Or:

```bash
uv run --python 3.12 scripts/leakcheck.py --project . --transcripts ~/.claude/projects --names names.txt --out-dir ./leak-out
```

## Test

`bash tests/run.sh` uses a fake project and fake transcripts (all keys marked FAKE). It asserts counts per type, that no full key appears in any output, that look-alikes and placeholders are not flagged, that the proposed hook blocks `.env` and allows `README.md`, that a dry-run scrub changes no file (checksums), and that `--apply` makes a valid `.bak`. Offline.

## Limits

- Shape matching only. It cannot tell whether a key is live.
- Rotate real keys you find. Scrubbing does not undo a leak.
- Deny-rule matching is an approximation. Confirm with `/permissions` in Claude Code.
- Claude Code documents no `.claudeignore`.

## License

MIT
