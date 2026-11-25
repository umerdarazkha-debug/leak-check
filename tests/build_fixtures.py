#!/usr/bin/env python3
"""Synthetic project + transcripts. Every key below is FAKE and made up for tests."""
import json, os, shutil
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "fixtures")
OPENAI = "sk-test-FAKE0123456789abcdefXYZ"
ANTH = "sk-ant-FAKE-api03-0123456789abcdefghij"
AWS = "AKIA" + "FAKEFAKEFAKEFAKE"
GH = "ghp_" + "FAKE" * 9
GHPAT = "github_pat_FAKE0123456789abcdefgh_FAKE"
GOOG = "AIzaFAKE0123456789abcdefghijklmnopqrstu"
SK_LIVE = "sk_live_FAKE0123456789abcdef"
PK_LIVE = "pk_live_FAKE0123456789abcdef"
SLACK = "xoxb-FAKE-0123456789-abcdefgh"
JWT = "eyJFAKEHEADER12.eyJFAKEPAYLOAD12.FAKESIGNATURE12"
DBPASS = "hunter2FAKEpassword"
def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f: f.write(text)
def main():
    for d in ("project", "transcripts", "names.txt"):
        p = os.path.join(ROOT, d)
        if os.path.isdir(p): shutil.rmtree(p)
        elif os.path.exists(p): os.remove(p)
    P = os.path.join(ROOT, "project")
    w(P + "/.env", "OPENAI_API_KEY=%s\nDB_PASSWORD=%s\nMAX_TOKENS=100000\nAPI_KEY=your_api_key_here\nEMPTY_SECRET=\n" % (OPENAI, DBPASS))
    w(P + "/config.py", "AWS = '%s'\nSTRIPE_SECRET = '%s'\nSTRIPE_PUB = '%s'\nGOOGLE = '%s'\n" % (AWS, SK_LIVE, PK_LIVE, GOOG))
    w(P + "/src/app.js", "const gh = '%s';\nconst pat = '%s';\nconst slack = '%s';\nconst a = '%s';\nconst jwt = '%s';\n" % (GH, GHPAT, SLACK, ANTH, JWT))
    w(P + "/notes.md", """Contact demo.person@example.com or billing@example.org.
Call +1 202 555 0143 or 0300-1234567 or (202) 555-0188.
Client: Ayesha Traders signed on Monday. Demo Client Ltd is next.
Lookalikes that are not secrets: task-sk-learn, sk-learn, AKIA-not-a-key, ghp_short, node@18.0.0,
version 10.20.30.40, order 2026-11-26, AIzaShort, sk_live_ (no value), @types/node.
""")
    w(P + "/keys/server.pem", "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----\n")
    w(P + "/.claude/settings.json", json.dumps({"permissions": {"deny": ["Read(./.env)"]}}, indent=2))
    w(P + "/README.md", "Plain readme with nothing private.\n")
    w(os.path.join(ROOT, "names.txt"), "Ayesha Traders\nDemo Client Ltd\n")
    T = os.path.join(ROOT, "transcripts", "-home-demo-app")
    lines = [
        {"type": "user", "message": {"role": "user", "content": "please read my env"}},
        {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
            "content": "OPENAI_API_KEY=%s\nDB_PASSWORD=%s\nMAX_TOKENS=100000\n" % (OPENAI, DBPASS)}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "Your key %s and token %s. Mail demo.person@example.com about Ayesha Traders." % (ANTH, JWT)}]}},
        {"type": "user", "message": {"role": "user", "content": "nothing private in this line, only sk-learn and node@18.0.0"}},
    ]
    w(T + "/s1.jsonl", "\n".join(json.dumps(l) for l in lines) + "\n")
main()
