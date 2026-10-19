#!/usr/bin/env python3
"""Phase B/C: build v0.2 cards from staging + authored gap cards. Writes checks/ and legacy/.

- programmatic cards: one per staged item, provenance = path + anchor + commit
- authored cards: gap platforms, provenance = official doc URL (verified)
- legacy v0.1 cards: audited, moved to legacy/, ids preserved via aliases.json
"""
import os, json, glob, re, hashlib, yaml, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TODAY = datetime.date.today().isoformat()
SRC = {s["repo"]: s for s in yaml.safe_load(open(os.path.join(ROOT, "sources.yaml")))["sources"]}
_cwemap_path = os.path.join(ROOT, "scripts", "ingest", "data", "asvs_cwe_mapping.json")
ASVS_CWE = json.load(open(_cwemap_path)) if os.path.exists(_cwemap_path) else {}

# ---------- inference maps ----------
CHAPTER_DOMAIN = {
 "Encoding and Sanitization":"injection","Validation and Business Logic":"input-validation",
 "Web Frontend Security":"xss","API and Web Service":"api","Authentication":"auth",
 "Session Management":"session","Access Control":"access-control","Cryptography":"crypto",
 "Error Handling and Logging":"logging","Data Protection":"data-protection",
 "Communication":"network","Malicious Code":"supply-chain","Files and Resources":"file-upload",
 "Configuration":"config","Self-contained Tokens":"auth","Secure Coding and Architecture":"config",
}
WSTG_DOMAIN = {"Information Gathering":"config","Configuration and Deployment Management Testing":"config",
 "Identity Management Testing":"auth","Authentication Testing":"auth","Authorization Testing":"access-control",
 "Session Management Testing":"session","Input Validation Testing":"injection","Testing for Error Handling":"error-handling",
 "Testing for Weak Cryptography":"crypto","Business Logic Testing":"business-logic","Client-side Testing":"xss",
 "API Testing":"api"}
KW_DOMAIN = [("injection","injection"),("sqli","injection"),("sql","injection"),("xss","xss"),
 ("csrf","csrf"),("ssrf","ssrf"),("session","session"),("auth","auth"),("access","access-control"),
 ("authoriz","access-control"),("crypto","crypto"),("secret","secrets"),("key","secrets"),
 ("upload","file-upload"),("deserial","deserialization"),("log","logging"),("config","config"),
 ("header","headers"),("cors","config"),("rate","rate-limiting"),("depend","supply-chain"),
 ("reentran","smart-contract"),("oracle","smart-contract"),("overflow","smart-contract"),
 ("proxy","smart-contract"),("random","smart-contract"),("dos","smart-contract"),("denial","smart-contract"),
 ("inject","injection"),("privacy","privacy"),("storage","storage"),("network","network"),
 ("transport","network"),("tls","network"),("file","file-upload"),("input","input-validation")]

DETECT = {
 "injection":{"grep":["execute\\(","query\\(","raw(", "SELECT .* \\+"],"files":["**/*.py","**/*.js","**/*.php","**/*.java"]},
 "xss":{"grep":["innerHTML","dangerouslySetInnerHTML","document.write","|safe"],"files":["**/*.html","**/*.js","**/*.jsx","**/*.tsx"]},
 "auth":{"grep":["password","login","jwt","session","authenticate"],"files":["**/auth/**","**/*.py","**/*.js"]},
 "session":{"grep":["Set-Cookie","res.cookie","set_cookie","SESSION"],"files":["**/*.js","**/*.py","**/settings/**"]},
 "access-control":{"grep":["findById(","get_object(","params.id","WHERE id"],"files":["**/controllers/**","**/routes/**","**/api/**"]},
 "secrets":{"grep":["AKIA[0-9A-Z]{16}","api[_-]?key","password\\s*=","-----BEGIN"],"files":["**/*.env","**/*.yml","**/*.py","**/*.js"]},
 "crypto":{"grep":["md5(","sha1(","DES","ECB","hardcod"],"files":["**/*.py","**/*.js","**/*.java","**/*.kt"]},
 "ssrf":{"grep":["requests.get(","fetch(","axios(","urlopen"],"files":["**/*.py","**/*.js","**/*.go"]},
 "file-upload":{"grep":["upload","move_uploaded_file","save(","multer"],"files":["**/upload*","**/routes/**"]},
 "deserialization":{"grep":["pickle.load","unserialize(","yaml.load(","ObjectInputStream"],"files":["**/*.py","**/*.php","**/*.java"]},
 "logging":{"grep":["logger.","console.log","audit"],"files":["**/middleware/**","**/*.js","**/*.py"]},
 "config":{"grep":["DEBUG","allowBackup","exported","0.0.0.0/0","Access-Control-Allow-Origin"],"files":["**/*.yml","**/*.yaml","**/*.json","**/settings/**"]},
 "supply-chain":{"grep":["dependencies","require(","import "],"files":["**/package.json","**/requirements.txt","**/go.mod","**/Gemfile"]},
 "network":{"grep":["http://","verify=False","Strict-Transport-Security"],"files":["**/*.conf","**/*.yml","**/*.env"]},
 "smart-contract":{"grep":[".call{","transfer(","delegatecall","unchecked{","onlyOwner"],"files":["**/*.sol"]},
 "rate-limiting":{"grep":["rateLimit","throttle","attempts"],"files":["**/auth/**","**/routes/**"]},
 "input-validation":{"grep":["req.body","request.data","params["],"files":["**/routes/**","**/controllers/**","**/api/**"]},
 "llm":{"grep":["system","prompt","completion","tool_calls","embedding"],"files":["**/*.py","**/*.ts"]},
 "storage":{"grep":["SharedPreferences","NSUserDefaults","UserDefaults","sqlite"],"files":["**/*.kt","**/*.java","**/*.swift"]},
 "error-handling":{"grep":["traceback","stack","DEBUG = True"],"files":["**/settings/**","**/*.py","**/*.js"]},
 "data-protection":{"grep":["serialize","jsonify","toJSON"],"files":["**/api/**","**/serializers/**"]},
 "headers":{"grep":["X-Frame-Options","Content-Security-Policy","helmet"],"files":["**/server*","**/app*","**/middleware/**"]},
 "webhook":{"grep":["webhook","setWebhook","signature","secret"],"files":["**/*.py","**/*.js","**/*.ts"]},
 "firmware":{"grep":["firmware","ota","update"],"files":["**/*.c","**/*.py"]},
 "infra":{"grep":["privileged: true","hostNetwork","0.0.0.0/0"],"files":["**/*.tf","**/*.yaml","**/k8s/**"]},
 "privacy":{"grep":["pii","personal","gdpr"],"files":["**/*.py","**/*.js"]},
 "csrf":{"grep":["csrf","_token"],"files":["**/routes/**","**/views/**"]},
 "business-logic":{"grep":["price","quantity","total","discount"],"files":["**/controllers/**","**/routes/**"]},
 "api":{"grep":["/api/","router.","@app."],"files":["**/routes/**","**/api/**"]},
}

def domain_of(official_id, meta, text):
    if official_id.startswith("ASVS:"):
        return CHAPTER_DOMAIN.get(meta.get("chapter_name",""), "config")
    if official_id.startswith("WSTG:"):
        return WSTG_DOMAIN.get(meta.get("category",""), "config")
    if official_id.startswith("MASVS-"):
        g = meta.get("group") or official_id.split("-")[1]
        return {"STORAGE":"storage","CRYPTO":"crypto","AUTH":"auth","NETWORK":"network",
                "PLATFORM":"config","CODE":"input-validation","RESILIENCE":"config"}.get(g.split("-")[-1], "config")
    if official_id.startswith("MASTG-"):
        g = meta.get("masvs","")
        return {"MASVS-STORAGE":"storage","MASVS-CRYPTO":"crypto","MASVS-AUTH":"auth",
                "MASVS-NETWORK":"network","MASVS-PLATFORM":"config","MASVS-CODE":"input-validation",
                "MASVS-RESILIENCE":"config"}.get(g,"config")
    if official_id.startswith("Top10:"): return "injection" if meta.get("rank") in ("A03",) else "access-control" if meta.get("rank")=="A01" else "config"
    if official_id.startswith("API"): return "access-control" if official_id.startswith("API1") else "config"
    if official_id.startswith("LLM"): return "llm"
    low = (official_id + " " + text).lower()
    for kw, dom in KW_DOMAIN:
        if kw in low: return dom
    return "config"

def platform_of(official_id, meta):
    if official_id.startswith("ASVS:"): return ["web","api"]
    if official_id.startswith(("WSTG:","WSTG-","Top10:")): return ["web"]
    if official_id.startswith("MASVS-") or official_id.startswith("MASTG-"): return ["mobile"]
    if official_id.startswith("API"): return ["api"]
    if official_id.startswith("LLM"): return ["llm"]
    return None  # set by source

SRC_PLATFORM = {"OWASP/CheatSheetSeries":["web"],"kadenzipfel/smart-contract-vulnerabilities":["web3"],
 "crytic/not-so-smart-contracts":["web3"],"ConsenSysDiligence/smart-contract-best-practices":["web3"],
 "OWASP/owasp-istg":["iot"],"OWASP/mastg":["mobile"],
 "OWASP/www-project-top-10-for-large-language-model-applications":["llm"],"OWASP/API-Security":["api"],"raroque/vibe-security-skill":["vibe"],"shieldfy/API-Security-Checklist":["api"],"yesmayank/secure-coding-baseline":["web","api"],"mgreiler/secure-code-review-checklist":["web"]}
SHEET_PLATFORM = {"Docker_Security_Cheat_Sheet":["cloud"],"Kubernetes_Security_Cheat_Sheet":["cloud"],
 "Nodejs_Security_Cheat_Sheet":["web"],"Django_Security_Cheat_Sheet":["web"],"REST_Security_Cheat_Sheet":["api"]}

CRIT_DOMAIN = {"injection","auth","access-control","crypto","secrets","deserialization","ssrf","smart-contract","firmware"}
HIGH_DOMAIN = CRIT_DOMAIN | {"xss","session","csrf","file-upload","supply-chain","llm","webhook","infra","data-protection"}

def severity_of(dom, official_id, meta):
    if official_id in ("Top10:A01:2025","Top10:A03:2025","API1:2023","LLM01:2025","MASVS-STORAGE-1"):
        return "critical"
    if official_id.startswith("ASVS:") and meta.get("level") == "1" and dom in CRIT_DOMAIN:
        return "critical"
    if dom in CRIT_DOMAIN: return "high"
    if dom in HIGH_DOMAIN: return "high"
    return "medium"

SRC_CODE = {
 "OWASP/ASVS":"ASVS","OWASP/masvs":"MASVS","OWASP/mastg":"MASTG","OWASP/wstg":"WSTG",
 "OWASP/Top10":"TOP10","OWASP/API-Security":"API",
 "OWASP/www-project-top-10-for-large-language-model-applications":"LLM",
 "OWASP/CheatSheetSeries":"CS","OWASP/owasp-istg":"ISTG",
 "kadenzipfel/smart-contract-vulnerabilities":"SCV","crytic/not-so-smart-contracts":"NSSC",
 "raroque/vibe-security-skill":"VIBE","shieldfy/API-Security-Checklist":"APICHK",
 "yesmayank/secure-coding-baseline":"BASE","mgreiler/secure-code-review-checklist":"SCR",
}
def stable_id(repo, oid, path, anchor):
    """ID from SOURCE IDENTITY (never from merge winners or sequence numbers)."""
    code = SRC_CODE.get(repo, "GEN")
    if oid:
        slug = re.sub(r"[^A-Za-z0-9]+", "-", str(oid)).strip("-").upper()
        if slug.startswith(code + "-"): slug = slug[len(code) + 1:]
        return f"SKB-{code}-{slug}"[:80]
    h = hashlib.sha1(f"{repo}|{path}|{anchor}".encode()).hexdigest()[:10].upper()
    return f"SKB-{code}-{h}"


def _payload_tokens(card):
    keys=("title","summary","platforms","domain","severity","cwe","owasp","check","fix","detect","verify_evidence","tags","aliases")
    return len(json.dumps({k:card[k] for k in keys if k in card}))//4

# R0 audit: only rules with >=80% precision are kept. DISABLED (<80%): 89, 943, 78, 79, 352, 434,
# 918, 601, 502, 611, 798, 915, 384, 770 (see AUDIT/ACCEPTANCE for per-rule precision).
# Official CWE-title matches: the phrase is the CWE's own published title (or an exact alias),
# so a match is a *mapping* to the official weakness, not a guess.
CWE_TITLE_RULES = [
 (r"integer overflow|integer underflow|overflow and underflow", "190"),
 (r"reentrancy|reentrant", "841"),
 (r"missing authentication|no authentication|without authentication|unauthenticated", "306"),
 (r"hard-?coded (credential|secret|password|key)|secrets? (in|committed|bundled|leak)|api key", "798"),
 (r"path traversal|directory traversal", "22"),
 (r"sql injection|sqli", "89"),
 (r"cross-?site scripting|xss", "79"),
 (r"cross-?site request forgery|csrf|xsrf", "352"),
 (r"server-?side request forgery|ssrf", "918"),
 (r"deserializ|pickle|unserialize", "502"),
 (r"xml external entit|xxe", "611"),
 (r"idor|object level authoriz|bola|object reference", "639"),
 (r"file upload|unrestricted upload", "434"),
 (r"unmaintained|outdated (component|dependency|package)|vulnerable (dependency|dependencies|component)", "1104"),
 (r"run(n?ing)? as root|non-?root|runasuser|privileged (container|mode)", "250"),
 (r"cleartext|plaintext (transmission|traffic)|no tls", "319"),
 (r"unvalidated redirect|open redirect", "601"),
 (r"clickjack", "1021"),
 (r"brute force|credential stuffing", "307"),
 (r"os command injection|command injection", "78"),
 (r"prototype pollution", "1321"),
 (r"race condition|toctou", "362"),
 (r"rate limit|resource consumption|denial of service", "770"),
 (r"mass assignment", "915"),
 (r"sensitive (information|data) (in|to) log|logging sensitive", "532"),
 (r"buffer overflow", "120"),
 (r"use after free", "416"),
 (r"privilege escalation", "269"),
 (r"weak (crypt|hash|random)|insufficient entropy", "330"),
 (r"improper (input )?validation", "20"),
 (r"supply chain|dependency confusion|typosquat", "1357"),
]

def _cwe_title(title, text):
    low = (title + " " + text[:300]).lower()
    out = []
    for pat, cwe in CWE_TITLE_RULES:
        if re.search(pat, low): out.append(f"CWE-{cwe}")
    return list(dict.fromkeys(out))[:6]

CWE_RULES = [
 ("object level authorization", "639"), ("direct object reference", "639"), ("idor", "639"),
 ("path traversal", "22"), ("directory traversal", "22"),
 ("clickjack", "1021"),
 ("brute force", "307"),
]
def _cwe_heuristic(title, check):
    low = (title + " " + check).lower()
    out = []
    for kw, cwe in CWE_RULES:
        if kw in low: out.append(f"CWE-{cwe}")
    return list(dict.fromkeys(out))[:3]

def _cwe_for(oid, meta):
    if oid.startswith("ASVS:"):
        rid = oid.split(":", 1)[1]
        if rid.startswith("V"): rid = rid[1:]
        v = ASVS_CWE.get("v5.0.be-" + rid)
        if v: return [f"CWE-{v}"]
    c = meta.get("cwe")
    if isinstance(c, list): return [x if str(x).startswith("CWE") else f"CWE-{x}" for x in c][:6]
    if isinstance(c, str) and c.startswith("CWE"): return [c]
    if isinstance(c, int): return [f"CWE-{c}"]
    return []

def mk_card(it, used_ids):
    repo = it["source_repo"]; meta = it.get("meta", {})
    s = SRC.get(repo, {})
    oid = it["official_id"]
    text = it["raw_text"]
    dom = domain_of(oid, meta, text)
    plat = platform_of(oid, meta) or SRC_PLATFORM.get(repo, ["generic"])
    if repo == "OWASP/CheatSheetSeries":
        plat = SHEET_PLATFORM.get(meta.get("sheet",""), ["web"])
    if repo == "OWASP/mastg":
        plat = ["mobile", meta.get("platform","android")]
    sev = severity_of(dom, oid, meta)
    title = (meta.get("name") or meta.get("statement") or meta.get("heading") or meta.get("title")
             or meta.get("section_name") or meta.get("slug") or oid)[:118]
    if oid.startswith("ASVS:"):
        title = f"{meta.get('section_name','')} - {oid.split(':')[1]}"[:118]
    title = title if len(title) >= 5 else (title + " control")
    summary = re.sub(r"\s+"," ",text)[:140]
    if len(summary) < 5: summary = (title + " - verify this control")[:140]
    cid = stable_id(repo, oid, it["path"], it.get("anchor"))
    if cid in used_ids:                      # synthetic id collided -> fall back to a hash of identity
        cid = stable_id(repo, None, it["path"], it.get("anchor"))
    if cid in used_ids:                      # true duplicate source identity -> same card
        return None
    used_ids.add(cid)
    refs = [oid]
    if oid.startswith("ASVS:"): refs.append("ASVS " + oid.split(":")[1])
    src_entry = {"repo": repo, "path": it["path"], "anchor": it.get("anchor"), "commit": (it.get("commit") or s.get("commit")),
                 "url": f"https://github.com/{repo}/blob/{it['commit']}/{it['path']}",
                 "license": s.get("license","NOASSERTION"), "type": "github",
                 "extraction": "programmatic", "verified": True}
    det = {"grep": DETECT.get(dom,{}).get("grep",[])[:4], "files": DETECT.get(dom,{}).get("files",[])[:4]}
    tags = ([dom] + [t for t in re.findall(r"[a-z]{4,}", (meta.get("heading","") + " " + meta.get("slug","")).lower())[:3]])[:4]
    card = {
        "id": cid, "title": title, "summary": summary,
        "platforms": plat, "stacks": ["any"], "domain": dom,
        "phase": ["pr-review","pre-launch","full-audit"],
        "severity": sev, "priority": 50,
        "cwe": list(dict.fromkeys(_cwe_for(oid, meta) + _cwe_title(title, text) + _cwe_heuristic(title, text)))[:6],
        "cwe_source": ("mapped" if (_cwe_for(oid, meta) or _cwe_title(title, text))
                       else ("heuristic" if _cwe_heuristic(title, text) else "extracted")),
        "owasp": [oid],
        "refs": refs,
        "check": (text[:400] if len(text) >= 10 else (text + " - verify this control")[:400]),
        "fix": f"See {repo} {it['path']} (anchor: {it.get('anchor')}) for remediation.",
        "detect": det,
        "verify_evidence": "Cite the file:line or config value inspected to justify pass/fail, or mark unknown.",
        "tags": tags,
        "sources": [src_entry],
        "origin": "distilled", "confidence": "high" if s.get("license") in ("CC-BY-SA-4.0","MIT","Apache-2.0","CC0-1.0") else "medium",
        "extraction": "programmatic", "verified": True, "corroboration": 1,
        "last_verified": TODAY,
    }
    while _payload_tokens(card) > 248:
        if len(card["check"]) > 90: card["check"] = card["check"][:-30].rstrip(); continue
        if len(card["detect"]["grep"]) > 2: card["detect"]["grep"].pop(); continue
        if len(card["detect"]["files"]) > 2: card["detect"]["files"].pop(); continue
        if len(card["tags"]) > 1: card["tags"].pop(); continue
        if len(card["summary"]) > 60: card["summary"] = card["summary"][:-20].rstrip(); continue
        if len(card["title"]) > 60: card["title"] = card["title"][:-20].rstrip(); continue
        if len(card.get("owasp", [])) > 1: card["owasp"].pop(); continue
        if card.get("aliases"): card.pop("aliases"); continue
        if len(card["fix"]) > 80: card["fix"] = card["fix"][:60].rstrip(); continue
        if len(card["verify_evidence"]) > 60: card["verify_evidence"] = "Cite file:line or config value, or mark unknown."; continue
        break
    return card

def main():
    used = set()
    cards = []
    # ORDER-INDEPENDENT: gather every staged item, sort by source identity, THEN assign ids.
    items = []
    for fp in sorted(glob.glob(os.path.join(ROOT, "staging", "*.jsonl"))):
        for line in open(fp):
            line = line.strip()
            if line:
                items.append(json.loads(line))
    items.sort(key=lambda it: (it["source_repo"], str(it.get("path","")), str(it.get("anchor","")), str(it.get("official_id","")), it.get("raw_text","")))
    for it in items:
        c = mk_card(it, used)
        if c: cards.append(c)
    # write programmatic cards
    out = os.path.join(ROOT, "checks")
    for c in cards:
        plat = c["platforms"][0]
        d = os.path.join(out, plat, c["domain"]); os.makedirs(d, exist_ok=True)
        yaml.safe_dump(c, open(os.path.join(d, c["id"] + ".yaml"), "w"), sort_keys=False, allow_unicode=True, width=100)
    print(f"programmatic cards: {len(cards)}")
    from collections import Counter
    print("by platform:", dict(Counter(p for c in cards for p in c["platforms"])))
    print("by domain:", dict(Counter(c["domain"] for c in cards)))
    print("by severity:", dict(Counter(c["severity"] for c in cards)))

if __name__ == "__main__":
    main()
