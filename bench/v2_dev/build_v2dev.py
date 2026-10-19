#!/usr/bin/env python3
"""R0: bench/v2_dev — >=40 NEW natural-language developer questions.

Written from the STANDARDS text (not from retrieval output). Expected answers are official refs.
Frozen with a hash before any retrieval change.
"""
import os, yaml, json, glob, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

Q = [
 # Cloudflare Workers / serverless
 ("how do I secure a Cloudflare Worker endpoint", ["CWE-306"]),
 ("my serverless function has no authentication", ["CWE-306"]),
 ("are worker secrets safe in environment bindings", ["CWE-798"]),
 ("how do I stop CORS wildcard on an edge function", ["CWE-942"]),
 ("how do I rate limit a serverless API", ["CWE-770"]),
 # Telegram bots
 ("how do I verify a telegram webhook secret", ["CWE-345"]),
 ("can someone steal my telegram bot token", ["CWE-798"]),
 ("how do I check telegram miniapp initData server side", ["CWE-345"]),
 ("how do I stop telegram admin commands being abused", ["CWE-862"]),
 # LLM / AI agent
 ("how do I stop prompt injection in a RAG app", ["LLM01:2025"]),
 ("my agent can call tools, how do I limit it", ["LLM06:2025"]),
 ("is it safe to render model output as HTML", ["LLM05:2025"]),
 ("how do I stop the model leaking the system prompt", ["LLM07:2025"]),
 ("how do I cap token spend on an LLM app", ["LLM10:2025"]),
 # REST APIs
 ("how do I stop broken object level authorization", ["API1:2023"]),
 ("my api accepts fields the client should not set", ["API6:2023"]),
 ("how do I stop the api returning too much data", ["API3:2023"]),
 ("how do I handle api versioning and deprecated routes", ["API9:2023"]),
 ("how do I stop SSRF in an api that fetches URLs", ["API7:2023"]),
 # Android / iOS
 ("where should an android app store tokens", ["MASVS-STORAGE-1"]),
 ("how do I stop cleartext traffic on android", ["MASVS-NETWORK-1"]),
 ("is my ios app transport security too lax", ["MASVS-NETWORK-1"]),
 ("how do I harden an android webview", ["MASTG-TEST-0047"]),
 ("how do I detect a rooted android device", ["MASVS-RESILIENCE-1"]),
 # Smart contracts
 ("how do I stop reentrancy in solidity", ["CWE-841"]),
 ("how do I protect an onlyOwner function", ["CWE-284"]),
 ("is my price oracle manipulable", ["CWE-345"]),
 ("how do I avoid integer overflow in solidity", ["CWE-190"]),
 # Docker / CI
 ("how do I stop secrets leaking in github actions", ["CWE-532"]),
 ("how do I run a container as non root", ["CWE-250"]),
 ("how do I scan a docker image for vulnerabilities", ["CWE-1104"]),
 ("how do I stop a privileged kubernetes pod", ["CWE-250"]),
 # Web basics
 ("how do I prevent sql injection", ["CWE-89"]),
 ("how do I prevent cross site scripting", ["CWE-79"]),
 ("how do I stop csrf on my forms", ["CWE-352"]),
 ("how do I store passwords safely", ["CWE-916"]),
 ("what cookie flags do I need", ["CWE-614"]),
 ("how do I stop open redirects", ["CWE-601"]),
 ("how do I stop insecure deserialization", ["CWE-502"]),
 ("how do I stop path traversal in a file download", ["CWE-22"]),
 ("how do I validate an uploaded file", ["CWE-434"]),
 ("how do I stop xml external entity attacks", ["CWE-611"]),
 ("how do I prevent clickjacking", ["CWE-1021"]),
 ("how do I keep secrets out of git", ["CWE-798"]),
 ("how do I stop mass assignment", ["CWE-915"]),
 ("how do I add security headers", ["Top10:A02:2025"]),
]

def main():
    # keep only questions whose expected refs exist in the corpus (so the set is answerable)
    have=set()
    for p in glob.glob(os.path.join(ROOT,"checks","**","*.yaml"), recursive=True):
        c=yaml.safe_load(open(p))
        have|=set(map(str,c.get("owasp",[])))|set(map(str,c.get("refs",[])))|set(map(str,c.get("cwe",[])))
    qs=[]; unanswerable=[]
    for q,refs in Q:
        ok=[r for r in refs if r in have]
        if ok: qs.append({"q":q,"expect_refs":ok})
        else: unanswerable.append((q,refs))
    d=os.path.join(ROOT,"bench","v2_dev"); os.makedirs(d,exist_ok=True)
    body={"version":1,"frozen":True,"set":"v2_dev","queries":qs}
    yaml.safe_dump(body, open(os.path.join(d,"queries.yaml"),"w"), sort_keys=False, allow_unicode=True, width=100)
    h=hashlib.sha256(open(os.path.join(d,"queries.yaml"),"rb").read()).hexdigest()
    open(os.path.join(d,"FREEZE.txt"),"w").write(f"v2_dev frozen hash: {h}\nqueries: {len(qs)}\n")
    print(f"v2_dev queries: {len(qs)} (target >=40)")
    print(f"freeze hash: {h[:16]}")
    if unanswerable: print("unanswerable (dropped):", len(unanswerable), unanswerable[:5])

if __name__ == "__main__":
    main()
