#!/usr/bin/env python3
"""Generate tests/benchmark.yaml: labeled queries with expected check ids."""
import os, yaml, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cards = [yaml.safe_load(open(p)) for p in glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)]

# extra hand-written, harder queries (paraphrase, synonyms, cross-card)
MANUAL = [
 ("cross site scripting in react", ["SKB-WEB-XSS-0004"]),
 ("sql injection parameterized queries", ["SKB-WEB-INJECT-0003"]),
 ("cookie flags httponly secure", ["SKB-WEB-SESSION-0002"]),
 ("idor broken object level authorization", ["SKB-WEB-ACCESS-0006", "SKB-API-BOLA-0016"]),
 ("server side request forgery", ["SKB-WEB-SSRF-0007"]),
 ("csrf token state changing", ["SKB-WEB-CSRF-0005"]),
 ("api rate limiting brute force", ["SKB-WEB-RATE-0013", "SKB-API-RESOURCE-0019"]),
 ("telegram webhook secret token", ["SKB-TG-WEBHOOK-0034"]),
 ("telegram bot token leak", ["SKB-TG-SECRETS-0033"]),
 ("supabase row level security", ["SKB-VIBE-RLS-0071"]),
 ("firebase rules allow true", ["SKB-VIBE-FIREBASE-0072"]),
 ("electron contextisolation nodeintegration", ["SKB-DESK-ELECTRON-0046"]),
 ("chrome extension permissions minimize", ["SKB-EXT-PERMS-0042"]),
 ("prompt injection llm", ["SKB-LLM-INJECT-0065"]),
 ("smart contract reentrancy", ["SKB-W3-REENTRANCY-0060"]),
 ("android exported components", ["SKB-AND-COMPONENTS-0027"]),
 ("ios app transport security", ["SKB-IOS-ATS-0032"]),
 ("hardcoded secrets in git", ["SKB-GEN-SECRETS-0022"]),
 ("vulnerable dependencies sca", ["SKB-GEN-SCA-0023"]),
 ("kubernetes privileged pod", ["SKB-CLOUD-K8S-0054"]),
 ("iot default credentials", ["SKB-IOT-DEFAULTCREDS-0056"]),
 ("s3 public bucket", ["SKB-CLOUD-IAC-0052"]),
 ("slopsquatting hallucinated package", ["SKB-VIBE-SLOPSQUAT-0073"]),
 ("cors wildcard credentials", ["SKB-API-CORS-0021", "SKB-VIBE-CORS-0075"]),
]

def main():
    queries = []
    for c in cards:
        if c.get("aliases"):
            q = c["aliases"][0]
        else:
            q = f"{c['domain'].replace('-', ' ')} {' '.join(c.get('tags', [])[:2])}".strip()
        if len(q) < 4:
            continue
        queries.append({"query": q, "expect": [c["id"]], "platform": c["platforms"][0]})
    for q, exp in MANUAL:
        queries.append({"query": q, "expect": exp, "platform": None})
    out = {"version": 1, "targets": {"recall_at_5": 0.85}, "queries": queries}
    os.makedirs(os.path.join(ROOT, "tests"), exist_ok=True)
    with open(os.path.join(ROOT, "tests", "benchmark.yaml"), "w") as f:
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True, width=100)
    print(f"benchmark queries: {len(queries)} (auto {len(queries)-len(MANUAL)} + manual {len(MANUAL)})")

if __name__ == "__main__":
    main()
