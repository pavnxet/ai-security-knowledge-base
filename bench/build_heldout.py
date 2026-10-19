#!/usr/bin/env python3
"""Build bench/heldout_queries.yaml (frozen). Expected answers are OFFICIAL refs, not SKB ids."""
import os, json, glob, yaml, random
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Curated, hand-written developer questions. Expected = official refs (ASVS/MASVS/CWE/API/LLM/Top10).
CURATED = [
 ("how do I stop someone forging my Telegram webhook?", ["CWE-345"]),
 ("is my JWT validation actually safe?", ["ASVS:V9.1.1","ASVS:V10.1.1"]),
 ("how do I prevent SQL injection in my API?", ["ASVS:V1.2.1","Top10:A03:2025","WSTG-INPV-05"]),
 ("what stops cross-site scripting in React?", ["ASVS:V1.2.1","WSTG-CLNT-01"]),
 ("how do I store passwords safely?", ["ASVS:V6.2.1"]),
 ("my session cookies get stolen, what flags do I need?", ["ASVS:V3.4.1","WSTG-SESS-02"]),
 ("how do I stop CSRF on form posts?", ["WSTG-SESS-05","ASVS:V3.5.1"]),
 ("is my file upload endpoint dangerous?", ["ASVS:V12.2.1","WSTG-BUSL-09"]),
 ("someone can read other users' data by changing the id", ["API1:2023","ASVS:V8.2.1","CWE-639"]),
 ("how do I avoid leaking stack traces to users?", ["ASVS:V16.5.1","WSTG-ERRH-01"]),
 ("what security headers should my site send?", ["ASVS:V14.4.1"]),
 ("how do I stop SSRF in a URL-fetch feature?", ["ASVS:V1.3.6","WSTG-INPV-19"]),
 ("is my password reset flow safe from brute force?", ["ASVS:V2.2.1","WSTG-ATHN-03"]),
 ("how do I secure an S3 bucket?", ["CWE-284"]),
 ("my kubernetes pods run as root, is that bad?", ["CWE-250"]),
 ("how do I keep secrets out of my CI pipeline?", ["CWE-798","CWE-532"]),
 ("how do I check my dependencies for known CVEs?", ["CWE-1104","Top10:A06:2025"]),
 ("what stops reentrancy in a Solidity contract?", ["CWE-841"]),
 ("how do I protect an admin function in a smart contract?", ["CWE-284"]),
 ("is my price oracle manipulable?", ["CWE-345"]),
 ("how do I stop prompt injection in my LLM app?", ["LLM01:2025"]),
 ("my chatbot runs whatever the model outputs, is that safe?", ["LLM05:2025"]),
 ("how do I limit what an AI agent can do?", ["LLM06:2025"]),
 ("is my Supabase database readable by anyone?", ["CWE-284"]),
 ("my Firebase rules say allow read, write: if true - problem?", ["CWE-284"]),
 ("an AI wrote my app and might have hardcoded an API key", ["CWE-798"]),
 ("how do I stop a package that doesn't exist from being installed?", ["CWE-1357"]),
 ("is my Electron app safe from remote code?", ["CWE-693"]),
 ("how do I sandbox an Electron renderer?", ["CWE-693"]),
 ("what permissions should my Chrome extension ask for?", ["CWE-250"]),
 ("how do I stop my extension loading remote scripts?", ["CWE-829"]),
 ("my Android app stores tokens in SharedPreferences", ["MASVS-STORAGE-1","CWE-312"]),
 ("how do I stop cleartext traffic on Android?", ["MASVS-NETWORK-1","CWE-319"]),
 ("is my iOS app transport security too lax?", ["MASVS-NETWORK-1"]),
 ("my Android component is exported, is that a risk?", ["CWE-926"]),
 ("how do I secure an IoT device with a default password?", ["CWE-1392"]),
 ("how do I verify firmware updates are legitimate?", ["CWE-494"]),
 ("how do I stop mass assignment in my API?", ["API3:2023","CWE-915"]),
 ("my API returns too many fields", ["API3:2023"]),
 ("how do I rate limit my login endpoint?", ["API4:2023","CWE-307"]),
 ("is wildcard CORS with credentials a problem?", ["CWE-942","ASVS:V14.5.3"]),
 ("how do I prevent clickjacking?", ["ASVS:V14.4.1"]),
 ("what is broken access control and how do I fix it?", ["Top10:A01:2025"]),
 ("how do I stop insecure deserialization?", ["ASVS:V1.4.1","CWE-502"]),
 ("how should I log security events?", ["ASVS:V16.2.1"]),
 ("how do I store an API key on a mobile app safely?", ["MASVS-STORAGE-1"]),
 ("how do I stop a Telegram bot admin command being abused?", ["CWE-862"]),
 ("is my webhook signature check correct?", ["CWE-345"]),
 ("how do I stop client-side price tampering in checkout?", ["CWE-602"]),
 ("how do I secure a Cloudflare Worker?", ["CWE-306"]),
 ("my serverless function has no auth", ["CWE-306"]),
 ("how do I stop GraphQL introspection leaking schema?", ["API9:2023"]),
 ("how do I keep database backups safe?", ["ASVS:V8.3.1"]),
 ("is MD5 ok for hashing passwords?", ["ASVS:V6.2.1","CWE-916"]),
 ("how do I stop open redirects?", ["WSTG-CLNT-04"]),
 ("how do I validate file paths to stop traversal?", ["CWE-22","WSTG-INPV-01"]),
 ("how do I stop XML external entity attacks?", ["ASVS:V1.5.1","CWE-611"]),
 ("how do I protect against tabnabbing?", ["ASVS:V14.4.1"]),
 ("how do I securely implement remember-me?", ["ASVS:V3.3.1"]),
]

def main():
    random.seed(0)
    qs = [{"q": q, "expect_refs": r, "set": "curated"} for q, r in CURATED]

    # templated set drawn from standards (independent of card text; expected = official id)
    def sample(src, n):
        rows = [json.loads(l) for l in open(os.path.join(ROOT, "staging", src))]
        random.shuffle(rows)
        out = []
        for it in rows[:n]:
            oid = it["official_id"]
            lead = " ".join(it["raw_text"].split()[:9])
            out.append({"q": f"Does this hold: {lead}?", "expect_refs": [oid], "set": "templated"})
        return out
    for src, n in [("OWASP__ASVS.jsonl", 40), ("OWASP__wstg.jsonl", 20),
                   ("OWASP__masvs.jsonl", 10), ("OWASP__API-Security.jsonl", 5),
                   ("OWASP__www-project-top-10-for-large-language-model-applications.jsonl", 5),
                   ("OWASP__CheatSheetSeries.jsonl", 15)]:
        qs += sample(src, n)

    os.makedirs(os.path.join(ROOT, "bench"), exist_ok=True)
    yaml.safe_dump({"version": 1, "frozen": True, "queries": qs},
                   open(os.path.join(ROOT, "bench", "heldout_queries.yaml"), "w"),
                   sort_keys=False, allow_unicode=True, width=100)
    # owner slot
    if not os.path.exists(os.path.join(ROOT, "bench", "user_queries.yaml")):
        yaml.safe_dump({"note": "Add 20 real queries from your own projects here. Expected = official refs.",
                        "queries": []}, open(os.path.join(ROOT, "bench", "user_queries.yaml"), "w"), sort_keys=False)
    from collections import Counter
    print("heldout queries:", len(qs), dict(Counter(q["set"] for q in qs)))

if __name__ == "__main__":
    main()
