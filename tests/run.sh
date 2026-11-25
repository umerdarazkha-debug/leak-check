#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
fail=0
expect() { if grep -qF -- "$3" <<<"$2"; then echo "ok   $1"; else echo "FAIL $1: missing '$3'"; fail=1; fi; }
refute() { if grep -qF -- "$3" <<<"$2"; then echo "FAIL $1: should not contain '$3'"; fail=1; else echo "ok   $1"; fi; }
python3 tests/build_fixtures.py || { echo "fixture build failed"; exit 1; }
F=tests/fixtures
OUT=$(mktemp -d)
PY="uv run --python 3.12 scripts/leakcheck.py"
# the complete fake values; none of them may ever appear in any output
FULL="sk-test-FAKE0123456789abcdefXYZ sk-ant-FAKE-api03-0123456789abcdefghij AKIAFAKEFAKEFAKEFAKE ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE github_pat_FAKE0123456789abcdefgh_FAKE AIzaFAKE0123456789abcdefghijklmnopqrstu sk_live_FAKE0123456789abcdef pk_live_FAKE0123456789abcdef xoxb-FAKE-0123456789-abcdefgh eyJFAKEHEADER12.eyJFAKEPAYLOAD12.FAKESIGNATURE12 hunter2FAKEpassword demo.person@example.com billing@example.org 0300-1234567 Ayesha"
count() { grep -cE "^- $1: $2\$" <<<"$3"; }

out=$($PY --project $F/project --transcripts $F/transcripts --names $F/names.txt --out-dir "$OUT")
proj=$(sed -n '/^## Project files/,/^## What Claude can see/p' <<<"$out")
tr=$(sed -n '/^## Old transcripts/,$p' <<<"$out")

for pair in anthropic:1 openai:1 aws:1 github:2 google:1 stripe:2 slack:1 private_key:1 jwt:1 env_secret:1 email:2 phone:3 name:2; do
  t=${pair%%:*}; n=${pair##*:}
  [ "$(count $t $n "$proj")" = "1" ] && echo "ok   project-$t=$n" || { echo "FAIL project-$t expected $n"; fail=1; }
done
expect project-total "$proj" "Findings: 19 in 5 file(s)"
for pair in anthropic:1 openai:1 jwt:1 env_secret:1 email:1 name:1; do
  t=${pair%%:*}; n=${pair##*:}
  [ "$(count $t $n "$tr")" = "1" ] && echo "ok   transcript-$t=$n" || { echo "FAIL transcript-$t expected $n"; fail=1; }
done
expect transcript-total "$tr" "Findings: 6 in 1 file(s)"
expect masked-openai "$out" ".env:1  openai  sk-t****"
expect masked-env "$out" "DB_PASSWORD=hunt****"
expect masked-name "$out" "notes.md:3  name  Ayes****"

# lookalikes and placeholders are not flagged
refute lookalike-line "$out" "notes.md:4"
refute lookalike-line5 "$out" "notes.md:5"
refute placeholder "$out" ".env:4"
refute number-token "$out" ".env:3"
refute empty-secret "$out" ".env:5"
refute readme-clean "$out" "README.md"
refute transcript-lookalike "$out" "s1.jsonl:4"

# full values never printed or written
leak=0
for k in $FULL; do
  if grep -qF -- "$k" <<<"$out" || grep -rqF -- "$k" "$OUT"; then echo "FAIL full value printed: ${k:0:4}****"; leak=1; fail=1; fi
done
[ $leak -eq 0 ] && echo "ok   no-full-values-in-output"

# what Claude can see
expect see-env-blocked "$out" "- .env: blocked by Read(./.env)"
expect see-pem-open "$out" "- keys/server.pem: NOT blocked, Claude can read it"
expect see-claudeignore "$out" ".claudeignore present: no"
expect see-files "$out" "Files Claude could read here (skipping .git, node_modules and similar): 7"

# proposals
grep -q '"Read(./keys/server.pem)"' "$OUT/proposed-settings.json" && echo "ok   proposal-has-pem" || { echo "FAIL proposal pem"; fail=1; }
grep -q '"Read(./.env)"' "$OUT/proposed-settings.json" && echo "ok   proposal-has-env" || { echo "FAIL proposal env"; fail=1; }
jq -e '.hooks.PreToolUse[0].matcher == "Read"' "$OUT/proposed-settings.json" >/dev/null && echo "ok   proposal-hook-matcher" || { echo "FAIL hook matcher"; fail=1; }
echo '{"tool_name":"Read","tool_input":{"file_path":"/p/.env"}}' | bash "$OUT/proposed-hook.sh" 2>/dev/null; [ $? -eq 2 ] && echo "ok   hook-blocks-env" || { echo "FAIL hook env"; fail=1; }
echo '{"tool_name":"Read","tool_input":{"file_path":"/p/id_rsa"}}' | bash "$OUT/proposed-hook.sh" 2>/dev/null; [ $? -eq 2 ] && echo "ok   hook-blocks-key" || { echo "FAIL hook key"; fail=1; }
echo '{"tool_name":"Read","tool_input":{"file_path":"/p/README.md"}}' | bash "$OUT/proposed-hook.sh" 2>/dev/null; [ $? -eq 0 ] && echo "ok   hook-allows-readme" || { echo "FAIL hook readme"; fail=1; }

# dry-run scrub changes nothing
sums() { find "$1" -type f | sort | xargs shasum | shasum; }
T=$(mktemp -d); cp -R $F/transcripts "$T/tr"
b=$(sums "$T/tr")
out=$($PY --transcripts "$T/tr" --names $F/names.txt --scrub --out-dir "$OUT")
a=$(sums "$T/tr")
[ "$b" = "$a" ] && echo "ok   dry-run-unchanged" || { echo "FAIL dry-run modified files"; fail=1; }
expect dry-label "$out" "DRY RUN, no file changed"
expect dry-count "$out" "-home-demo-app/s1.jsonl: 4 replacement(s)"
[ ! -e "$T/tr/-home-demo-app/s1.jsonl.bak" ] && echo "ok   dry-no-bak" || { echo "FAIL dry bak"; fail=1; }

# apply: secrets replaced, bak kept, file still valid JSONL, PII untouched without --scrub-pii
orig=$(shasum < "$T/tr/-home-demo-app/s1.jsonl")
out=$($PY --transcripts "$T/tr" --names $F/names.txt --scrub --apply --out-dir "$OUT")
expect apply-count "$out" "-home-demo-app/s1.jsonl: 4 replacement(s) (backup written as .bak)"
[ "$(shasum < "$T/tr/-home-demo-app/s1.jsonl.bak")" = "$orig" ] && echo "ok   bak-is-original" || { echo "FAIL bak"; fail=1; }
f="$T/tr/-home-demo-app/s1.jsonl"
jq -e . "$f" >/dev/null && echo "ok   still-valid-json" || { echo "FAIL json broken"; fail=1; }
[ "$(grep -c REDACTED "$f")" -eq 2 ] && echo "ok   redacted-lines" || { echo "FAIL redacted lines"; fail=1; }
grep -qF "sk-test-FAKE" "$f" && { echo "FAIL openai remains"; fail=1; } || echo "ok   secrets-gone"
grep -qF "demo.person@example.com" "$f" && echo "ok   pii-kept-by-default" || { echo "FAIL pii removed"; fail=1; }
grep -qF "MAX_TOKENS=100000" "$f" && echo "ok   non-secret-kept" || { echo "FAIL nonsecret changed"; fail=1; }
out=$($PY --transcripts "$T/tr" --names $F/names.txt)
expect after-scrub-rescan "$out" "Findings: 2 in 1 file(s)"   # email + name remain
rm -rf "$T" "$OUT"

# bad input
$PY --project /nonexistent-dir >/dev/null 2>&1 && { echo "FAIL bad path accepted"; fail=1; } || echo "ok   bad-path-rejected"
[ $fail -eq 0 ] && echo "ALL PASS" || { echo "FAILED"; exit 1; }
