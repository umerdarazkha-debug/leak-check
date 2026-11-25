# Patterns and mechanisms

Checked 2026-11-26. Source for the mechanisms: Claude Code docs, "Settings files and precedence" (https://code.claude.com/docs/en/settings) and "Hooks reference" (https://code.claude.com/docs/en/hooks).

## Real protection mechanism

- `permissions.deny` in a settings file hides files from Claude's Read tool. The docs example is `"deny": ["Read(./.env)", "Read(./.env.*)"]`.
- Settings files: `~/.claude/settings.json` (user), `.claude/settings.json` (shared project), `.claude/settings.local.json` (project local). Lists such as `permissions.deny` merge across files.
- The docs fetched for this skill do not mention a `.claudeignore` file. Treat it as not supported.
- A `PreToolUse` hook gets JSON on stdin (`tool_name`, `tool_input`). For the Read tool the path is `tool_input.file_path` (not shown in the page excerpt we read, so this is UNVERIFIED: test the hook once). Exit code 2 blocks the call and shows stderr to Claude. A JSON reply with `hookSpecificOutput.permissionDecision: "deny"` also blocks.
- A `matcher` of plain letters (`"Read"`) matches that tool name exactly.
- The hook command in settings uses `${CLAUDE_PROJECT_DIR}/.claude/hooks/<script>`.

## Secret patterns (shape only, no network check)

| Type | Shape |
|---|---|
| anthropic | `sk-ant-` + 20 or more of `A-Za-z0-9_-` |
| openai | `sk-` (not `sk-ant-`) + 20 or more of `A-Za-z0-9_-`, optional `proj-`/`svcacct-`/`admin-` |
| aws | `AKIA` or `ASIA` + 16 uppercase letters or digits |
| github | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 or more alphanumerics; `github_pat_` + 22 or more |
| google | `AIza` + 35 characters |
| stripe | `sk_live_`, `pk_live_`, `rk_live_` + 16 or more alphanumerics |
| slack | `xox` + one of `a b p r s` + `-` + 10 or more |
| private_key | `-----BEGIN ... PRIVATE KEY-----` header |
| jwt | `eyJ...` `.` `eyJ...` `.` signature, each part 8 or more |
| env_secret | line `NAME=value`, NAME contains KEY, SECRET, TOKEN, PASSWORD or PASSWD; value 8 or more characters, not all digits, not a placeholder |
| email | `local@domain.tld` with an alphabetic TLD |
| phone | `+` international, `0300-1234567` style, `(202) 555-0188` style |
| name | whole-word, case-insensitive match of each line in `--names` |

Known gaps: keys split across lines, base64 blobs, passwords not in a `NAME=` line, phone numbers in other layouts, Stripe test keys (not flagged on purpose).
