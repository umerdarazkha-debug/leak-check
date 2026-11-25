---
name: leak-check
description: Find secrets and private data that Claude Code can see or has already stored. Scans a project folder and old session transcripts for API keys (OpenAI, Anthropic, AWS, GitHub, Google, Stripe, Slack), private key blocks, JWTs, secret-looking .env lines, emails, phone numbers and a list of client or person names you supply. Matches are always printed masked. Shows which secret files Claude can read, proposes permissions.deny rules and a PreToolUse hook (proposals only), and can scrub transcripts after making a backup (dry-run by default). Use when the user says "is Claude seeing my .env", "did I paste a key into chat", "check for leaked secrets", "clean my transcripts", "client names in my logs", "privacy check", "leak check".
---

# Leak check

Finds secrets and private data. Prints every match masked (first 4 characters + `****`). Changes nothing unless the user asks for `--apply --scrub`.

## Steps

1. Ask which project folder to check and whether to check old transcripts too (normally `~/.claude/projects`). Ask if they have client or person names to look for. If yes, write one name per line into a text file (outside the project, not committed).
2. Run (from the skill folder):

```bash
uv run --python 3.12 scripts/leakcheck.py --project ~/path/to/project \
  --transcripts ~/.claude/projects --names names.txt --out-dir ./leak-out
```

   Either `--project` or `--transcripts` alone is fine. `--user-settings ~/.claude/settings.json` adds the user settings file to the deny-rule check.
3. Report in plain words:
   - Counts per type, and the masked list with file and line.
   - Which secret-looking files Claude can read and which are blocked by a deny rule.
   - Where secrets sit in old transcripts.
4. Tell the user to rotate any real key found. A scrubbed log does not undo a leak.
5. Show the proposals in `./leak-out`: `proposed-settings.json` (permissions.deny rules plus a PreToolUse hook entry) and `proposed-hook.sh`. The skill never installs them. If the user wants them, tell them to merge the JSON into `.claude/settings.json` and copy the hook to `.claude/hooks/block-secret-reads.sh` themselves. Then suggest `/permissions` and `/hooks` in Claude Code to confirm they loaded.
6. Scrubbing transcripts. First show the plan:

```bash
uv run --python 3.12 scripts/leakcheck.py --transcripts ~/.claude/projects --scrub
```

   Only after a clear yes, add `--apply`. Each changed file is copied to `<file>.bak` first. Default scrub covers secret types only. `--scrub-pii` also replaces emails, phones and names. Do not scrub a session that is running right now.

## What is flagged

anthropic, openai, aws, github, google, stripe (`sk_live_`, `pk_live_`, `rk_live_`), slack, private_key (BEGIN header), jwt, env_secret (`NAME_WITH_KEY/SECRET/TOKEN/PASSWORD=value`, skipping empty values, short values, numbers and placeholders like `your_key_here`), email, phone, name. Patterns and known gaps: `references/patterns.md`.

## Limits

- Pattern matching finds known shapes. It misses unknown formats and splits keys.
- The deny-rule check approximates how Claude Code matches paths. Confirm in `/permissions`.
- A Read deny rule covers the Read tool. A shell `cat` is another tool. Check the permissions docs for Bash rules and sandboxing.
- Claude Code documents no `.claudeignore` file. The script reports if one exists but does not count it as protection.
- The project scan skips `.git`, `node_modules` and similar folders, binary files, and files over 2 MB.
