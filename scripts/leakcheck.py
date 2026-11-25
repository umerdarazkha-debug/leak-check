#!/usr/bin/env python3
"""leak-check: find secrets and private data that Claude can see in a project or has stored in transcripts.

Stdlib only. Matches are ALWAYS printed masked (first 4 characters + ****).
Default is read-only. The only thing that edits files is: --apply --scrub (transcripts only, .bak first).
Settings and hook proposals are written to files in --out-dir and never applied.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys

NB = r"(?<![A-Za-z0-9_-])"
SECRET_TYPES = ["anthropic", "openai", "aws", "github", "google", "stripe", "slack", "private_key", "jwt", "env_secret"]
PII_TYPES = ["email", "phone", "name"]
ALL_TYPES = SECRET_TYPES + PII_TYPES

# (type, compiled regex). Order is priority when two matches overlap.
PATTERNS = [
    ("anthropic", re.compile(NB + r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai", re.compile(NB + r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("aws", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("github", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("google", re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9_-])")),
    ("stripe", re.compile(r"(?<![A-Za-z0-9_])(?:sk|pk|rk)_live_[0-9A-Za-z]{16,}")),
    ("slack", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[0-9A-Za-z-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
ENV_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Za-z0-9_]*)[ \t]*=[ \t]*"
    r"(?P<val>\"[^\"\n]*\"|'[^'\n]*'|[^\s#\"']+)", re.I | re.M)
PLACEHOLDER = re.compile(r"^(your[-_ ]|\[redacted|<|\$|\{\{|x{3,}|\*{3,}|changeme|change-me|example|placeholder|replace|none$|null$|true$|false$|todo|dummy)", re.I)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])")
PHONE_RES = [
    re.compile(r"(?<![\w+])\+\d{1,3}[ -]?\d{2,4}[ -]?\d{3,4}[ -]?\d{3,4}(?!\d)"),
    re.compile(r"(?<![\w-])0\d{3}[- ]?\d{7}(?![\w-])"),
    re.compile(r"(?<![\w.-])\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\w-]|\.\d)"),
]

# File names that usually hold secrets (used for the "what Claude can see" list and the proposal).
SECRET_FILE_PATTERNS = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*",
                        "credentials*", "secrets.*", ".npmrc", ".netrc", "service-account*.json"]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build"}
MAX_BYTES = 2 * 1024 * 1024


def mask(v):
    v = v.strip()
    return (v[:4] if len(v) > 4 else "") + "****"


def real_secret_value(val):
    v = val.strip("\"'")
    if len(v) < 8 or v.isdigit() or PLACEHOLDER.match(v):
        return None
    return v


def scan_text(text, names):
    """Return list of (type, start, end, label) for non-overlapping matches. label is already masked."""
    cands = []
    for t, rx in PATTERNS:
        for m in rx.finditer(text):
            cands.append((t, m.start(), m.end(), mask(m.group(0))))
    for m in ENV_RE.finditer(text):
        v = real_secret_value(m.group("val"))
        if v is not None:
            s = m.start("val")
            cands.append(("env_secret", s, m.end("val"), "%s=%s" % (m.group("name"), mask(v))))
    for m in EMAIL_RE.finditer(text):
        cands.append(("email", m.start(), m.end(), mask(m.group(0))))
    for rx in PHONE_RES:
        for m in rx.finditer(text):
            cands.append(("phone", m.start(), m.end(), mask(m.group(0))))
    for n in names:
        for m in re.finditer(r"(?<![A-Za-z0-9])" + re.escape(n) + r"(?![A-Za-z0-9])", text, re.I):
            cands.append(("name", m.start(), m.end(), mask(m.group(0))))
    prio = {t: i for i, t in enumerate(ALL_TYPES)}
    cands.sort(key=lambda c: (prio[c[0]], c[1]))
    taken, out = [], []
    for c in cands:
        if any(c[1] < e and s < c[2] for s, e in taken):
            continue
        taken.append((c[1], c[2]))
        out.append(c)
    out.sort(key=lambda c: c[1])
    return out


def load_names(path):
    if not path:
        return []
    with open(os.path.expanduser(path), encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def is_text(path):
    try:
        with open(path, "rb") as f:
            return b"\0" not in f.read(4096)
    except OSError:
        return False


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            yield os.path.join(dirpath, fn)


def json_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            for s in json_strings(v):
                yield s
    elif isinstance(obj, list):
        for v in obj:
            for s in json_strings(v):
                yield s


def scan_file(path, names, jsonl):
    """Return list of (lineno, type, label)."""
    hits = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            texts = [line]
            if jsonl:
                try:
                    texts = list(json_strings(json.loads(line))) or [line]
                except ValueError:
                    texts = [line]
            for t in texts:
                for typ, s, e, label in scan_text(t, names):
                    hits.append((i, typ, label))
    return hits


# ---------- permissions ----------

def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def deny_rules(settings_paths):
    rules = []
    for p in settings_paths:
        d = read_json(p)
        if isinstance(d, dict):
            perm = d.get("permissions")
            if isinstance(perm, dict) and isinstance(perm.get("deny"), list):
                for r in perm["deny"]:
                    if isinstance(r, str):
                        rules.append((p, r))
    return rules


def glob_to_regex(g):
    g = g.replace("\\", "/")
    anchored = g.startswith("./") or g.startswith("/") or "/" in g.strip("/").replace("**/", "", 1)
    g = g[2:] if g.startswith("./") else g.lstrip("/")
    out, i = "", 0
    while i < len(g):
        c = g[i]
        if g[i:i + 3] == "**/":
            out += "(?:.*/)?"
            i += 3
        elif g[i:i + 2] == "**":
            out += ".*"
            i += 2
        elif c == "*":
            out += "[^/]*"
            i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(c)
            i += 1
    prefix = "" if anchored else "(?:.*/)?"
    return re.compile("^" + prefix + out + "(?:/.*)?$")


def read_denied(relpath, rules):
    for _, r in rules:
        m = re.match(r"^Read\((.*)\)$", r.strip())
        if m and glob_to_regex(m.group(1)).match(relpath):
            return r
    return None


def fnmatch_any(name, pats):
    import fnmatch
    return any(fnmatch.fnmatch(name, p) for p in pats)


# ---------- proposals ----------

HOOK_SH = r'''#!/usr/bin/env bash
# PROPOSED PreToolUse hook (leak-check). Review before use. Not installed by the skill.
# Blocks the Read tool when the file path looks like a secrets file. Exit code 2 blocks the call
# and the stderr text is shown to Claude. Reads the hook JSON from stdin (tool_input.file_path).
input="$(cat)"
path="$(printf '%s' "$input" | python3 -c 'import sys,json
try:
    print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))
except Exception:
    print("")' 2>/dev/null)"
base="$(basename -- "$path")"
case "$base" in
@@CASES@@
    echo "Blocked by leak-check hook: $base looks like a secrets file." >&2
    exit 2
    ;;
esac
case "$path" in
@@DIRS@@
    echo "Blocked by leak-check hook: $path is in a secrets folder." >&2
    exit 2
    ;;
esac
exit 0
'''


def build_proposals(extra_files):
    deny = ["Read(./.env)", "Read(./.env.*)", "Read(./**/.env)", "Read(./**/.env.*)", "Read(./secrets/**)",
            "Read(./**/*.pem)", "Read(./**/*.key)", "Read(./**/id_rsa*)", "Read(./**/id_ed25519*)",
            "Read(./**/credentials*)", "Read(./**/.npmrc)", "Read(./**/.netrc)"]
    for f in extra_files:
        r = "Read(./%s)" % f
        if r not in deny:
            deny.append(r)
    settings = {
        "permissions": {"deny": deny},
        "hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [
            {"type": "command", "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/block-secret-reads.sh"}]}]},
    }
    base_cases = [".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "credentials*", ".npmrc", ".netrc"]
    cases = "    " + "|".join(base_cases) + ")"
    dirs = "    */secrets/*|secrets/*)"
    return settings, HOOK_SH.replace("@@CASES@@", cases).replace("@@DIRS@@", dirs)


# ---------- scrub ----------

def scrub_file(path, names, types, apply_):
    """Return number of replacements. With apply_, write a .bak and rewrite changed lines."""
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        lines = f.readlines()
    count, new_lines = 0, []
    for line in lines:
        stripped = line.rstrip("\r\n")
        eol = line[len(stripped):]
        try:
            obj = json.loads(stripped)
            is_json = True
        except ValueError:
            obj, is_json = None, False
        n = 0

        def fix(s):
            nonlocal n
            ms = [m for m in scan_text(s, names) if m[0] in types]
            for typ, st, en, _ in reversed(ms):
                s = s[:st] + "[REDACTED]" + s[en:]
                n += 1
            return s

        def walk(o):
            if isinstance(o, str):
                return fix(o)
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v) for v in o]
            return o
        if is_json:
            new = walk(obj)
            if n:
                stripped = json.dumps(new, ensure_ascii=False, separators=(",", ":"))
        else:
            stripped = fix(stripped)
        count += n
        new_lines.append(stripped + eol)
    if count and apply_:
        bak = path + ".bak"
        k = 1
        while os.path.exists(bak):
            bak = "%s.bak%d" % (path, k)
            k += 1
        shutil.copy2(path, bak)
        with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
            f.writelines(new_lines)
    return count


# ---------- main ----------

def summarize(hits_by_file):
    counts = {}
    for hits in hits_by_file.values():
        for _, typ, _ in hits:
            counts[typ] = counts.get(typ, 0) + 1
    return counts


def print_area(title, root, hits_by_file, L):
    counts = summarize(hits_by_file)
    L.append("## %s" % title)
    L.append("")
    L.append("Folder: %s" % root)
    L.append("Findings: %d in %d file(s)" % (sum(counts.values()), len(hits_by_file)))
    L.append("")
    for t in ALL_TYPES:
        if counts.get(t):
            L.append("- %s: %d" % (t, counts[t]))
    if not counts:
        L.append("- nothing found")
    L.append("")
    for rel in sorted(hits_by_file):
        for ln, typ, label in hits_by_file[rel]:
            L.append("  %s:%d  %s  %s" % (rel, ln, typ, label))
    L.append("")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find secrets and private data in a project and in Claude Code transcripts. Output is masked.")
    ap.add_argument("--project", help="project folder Claude works in")
    ap.add_argument("--transcripts", help="folder of session .jsonl files (e.g. ~/.claude/projects)")
    ap.add_argument("--names", help="text file, one client or person name per line")
    ap.add_argument("--user-settings", help="optional user settings.json to include when checking deny rules")
    ap.add_argument("--out-dir", default=".", help="where proposed-settings.json and proposed-hook.sh are written")
    ap.add_argument("--scrub", action="store_true", help="rewrite transcripts replacing secrets with [REDACTED] (needs --apply)")
    ap.add_argument("--scrub-pii", action="store_true", help="with --scrub, also replace emails, phones and names")
    ap.add_argument("--apply", action="store_true", help="really rewrite files (with --scrub). Without it only a plan is printed")
    a = ap.parse_args(argv)
    if not a.project and not a.transcripts:
        ap.error("give --project and/or --transcripts")
    names = load_names(a.names)
    L = ["# Leak check", "", "All values below are masked: first 4 characters + ****. Nothing is printed in full.", ""]
    found_any = False
    extra_files = []

    if a.project:
        root = os.path.abspath(os.path.expanduser(a.project))
        if not os.path.isdir(root):
            print("Not found: %s" % root, file=sys.stderr)
            return 2
        hits, all_files, secret_files, big = {}, [], [], 0
        for p in walk_files(root):
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            all_files.append(rel)
            if fnmatch_any(os.path.basename(p), SECRET_FILE_PATTERNS):
                secret_files.append(rel)
            if os.path.getsize(p) > MAX_BYTES or not is_text(p):
                big += 1
                continue
            h = scan_file(p, names, False)
            if h:
                hits[rel] = h
        print_area("Project files", root, hits, L)
        found_any = found_any or bool(hits)
        spaths = [os.path.join(root, ".claude", "settings.json"), os.path.join(root, ".claude", "settings.local.json")]
        if a.user_settings:
            spaths.append(os.path.expanduser(a.user_settings))
        existing = [p for p in spaths if os.path.isfile(p)]
        rules = deny_rules(existing)
        L.append("## What Claude can see in this folder")
        L.append("")
        L.append("Files Claude could read here (skipping .git, node_modules and similar): %d" % len(all_files))
        L.append("Skipped as binary or over 2 MB when scanning: %d" % big)
        L.append("Settings files found: %s" % (", ".join(os.path.relpath(p, root) for p in existing) or "none"))
        L.append("Read deny rules found: %d" % sum(1 for _, r in rules if r.startswith("Read(")))
        L.append(".claudeignore present: %s (Claude Code documents no .claudeignore file. permissions.deny in settings.json is the documented way to hide files.)" % (
            "yes" if os.path.exists(os.path.join(root, ".claudeignore")) else "no"))
        L.append("")
        L.append("Secret-looking files in this folder:")
        for rel in secret_files:
            r = read_denied(rel, rules)
            L.append("- %s: %s" % (rel, ("blocked by %s" % r) if r else "NOT blocked, Claude can read it"))
            if not r:
                extra_files.append(rel)
        if not secret_files:
            L.append("- none")
        L.append("")
        L.append("Note: a Read deny rule stops Claude's Read tool. A shell command such as `cat .env` is a different tool. Check the permissions docs for Bash and sandbox settings. Rule matching here is an approximation. Confirm with /permissions in Claude Code.")
        L.append("")
        settings, hook = build_proposals(extra_files)
        od = os.path.expanduser(a.out_dir)
        os.makedirs(od, exist_ok=True)
        with open(os.path.join(od, "proposed-settings.json"), "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")
        hp = os.path.join(od, "proposed-hook.sh")
        with open(hp, "w", encoding="utf-8") as f:
            f.write(hook)
        os.chmod(hp, os.stat(hp).st_mode | stat.S_IXUSR)
        L.append("Proposals written (not applied): %s, %s" % (os.path.join(od, "proposed-settings.json"), hp))
        L.append("To use them, merge the JSON into .claude/settings.json yourself and copy the hook to .claude/hooks/block-secret-reads.sh.")
        L.append("")

    if a.transcripts:
        troot = os.path.abspath(os.path.expanduser(a.transcripts))
        if not os.path.isdir(troot):
            print("Not found: %s" % troot, file=sys.stderr)
            return 2
        thits = {}
        for p in walk_files(troot):
            if p.endswith(".jsonl"):
                h = scan_file(p, names, True)
                if h:
                    thits[os.path.relpath(p, troot).replace(os.sep, "/")] = h
        print_area("Old transcripts", troot, thits, L)
        found_any = found_any or bool(thits)
        if a.scrub:
            types = set(SECRET_TYPES) | (set(PII_TYPES) if a.scrub_pii else set())
            L.append("## Scrub plan (%s)" % ("APPLY" if a.apply else "DRY RUN, no file changed; add --apply to rewrite"))
            L.append("")
            total = 0
            for rel in sorted(thits):
                n = scrub_file(os.path.join(troot, rel), names, types, a.apply)
                if n:
                    total += n
                    L.append("- %s: %d replacement(s)%s" % (rel, n, " (backup written as .bak)" if a.apply else ""))
            L.append("")
            L.append("Total replacements: %d (%s)" % (total, "types: " + ", ".join(sorted(types))))
            L.append("")
        elif a.apply:
            L.append("--apply does nothing without --scrub.")
            L.append("")
    elif a.scrub:
        L.append("--scrub needs --transcripts.")
        L.append("")
    L.append("Rotate any real key that appears above. Scrubbing a log does not undo a leak.")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
