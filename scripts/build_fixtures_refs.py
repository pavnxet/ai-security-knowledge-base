#!/usr/bin/env python3
"""Write fixtures/<lab>.yaml (lab vuln -> check id) and references/index.yaml (Tier-3 links)."""
import os, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FIXTURES = {
 "juice-shop": {"platforms": ["web"], "source": "juice-shop/juice-shop",
   "maps": {"XSS (DOM/reflected)": ["SKB-WEB-XSS-0004"], "SQL injection": ["SKB-WEB-INJECT-0003"],
            "Broken authentication": ["SKB-WEB-AUTH-0001", "SKB-API-AUTH-0015"],
            "Broken access control / IDOR": ["SKB-WEB-ACCESS-0006", "SKB-API-BOLA-0016"],
            "Sensitive data exposure": ["SKB-API-DATAEXPOSURE-0018"], "No CSRF on some routes": ["SKB-WEB-CSRF-0005"],
            "Security misconfiguration": ["SKB-WEB-HEADERS-0011"]}},
 "dvwa": {"platforms": ["web"], "source": "digininja/DVWA",
   "maps": {"SQL injection": ["SKB-WEB-INJECT-0003"], "Reflected/Stored XSS": ["SKB-WEB-XSS-0004"],
            "CSRF": ["SKB-WEB-CSRF-0005"], "File inclusion/upload": ["SKB-WEB-FILEUP-0008"],
            "Weak session IDs": ["SKB-WEB-SESSION-0002"], "Brute force": ["SKB-WEB-RATE-0013"]}},
 "webgoat": {"platforms": ["web"], "source": "WebGoat/WebGoat",
   "maps": {"Injection": ["SKB-WEB-INJECT-0003"], "XSS": ["SKB-WEB-XSS-0004"],
            "Access control flaws": ["SKB-WEB-ACCESS-0006"], "Insecure deserialization": ["SKB-WEB-DESER-0009"],
            "SSRF": ["SKB-WEB-SSRF-0007"]}},
 "nodegoat": {"platforms": ["web", "api"], "source": "OWASP/NodeGoat",
   "maps": {"NoSQL injection": ["SKB-WEB-INJECT-0003"], "SSRF": ["SKB-WEB-SSRF-0007"],
            "Broken access control": ["SKB-WEB-ACCESS-0006"], "Unvalidated redirects": ["SKB-WEB-SSRF-0007"],
            "Sensitive data exposure": ["SKB-API-DATAEXPOSURE-0018"]}},
 "vampi": {"platforms": ["api"], "source": "erev0s/VAmPI",
   "maps": {"BOLA": ["SKB-API-BOLA-0016"], "Broken authentication": ["SKB-API-AUTH-0015"],
            "Mass assignment": ["SKB-API-MASSASSIGN-0017"], "Excessive data exposure": ["SKB-API-DATAEXPOSURE-0018"],
            "Lack of rate limiting": ["SKB-API-RESOURCE-0019"]}},
 "securityshepherd": {"platforms": ["web", "mobile"], "source": "OWASP/SecurityShepherd",
   "maps": {"Injection": ["SKB-WEB-INJECT-0003"], "XSS": ["SKB-WEB-XSS-0004"],
            "CSRF": ["SKB-WEB-CSRF-0005"], "Session management": ["SKB-WEB-SESSION-0002"]}},
 "dvia-v2": {"platforms": ["ios"], "source": "prateek147/DVIA-v2",
   "maps": {"Insecure data storage": ["SKB-MOB-STORAGE-0024"], "ATS bypass": ["SKB-IOS-ATS-0032"],
            "Jailbreak detection bypass": ["SKB-MOB-RESILIENCE-0030"], "Hardcoded secrets": ["SKB-MOB-APKSECRETS-0031"]}},
 "llmvault": {"platforms": ["llm"], "source": "CyberSunil/LLMVault",
   "maps": {"Prompt injection": ["SKB-LLM-INJECT-0065"], "Insecure output handling": ["SKB-LLM-OUTPUT-0066"],
            "Excessive agency": ["SKB-LLM-AGENCY-0067"], "Sensitive info disclosure": ["SKB-LLM-DISCLOSURE-0068"]}},
}

REFERENCES = [
 {"repo": "trimstray/the-book-of-secret-knowledge", "topics": ["cheatsheets", "tools", "manuals"], "tier": 3},
 {"repo": "Hack-with-Github/Awesome-Hacking", "topics": ["meta-list", "pentest", "research"], "tier": 3},
 {"repo": "lissy93/personal-security-checklist", "topics": ["privacy", "end-user", "checklist"], "tier": 3},
 {"repo": "sbilly/awesome-security", "topics": ["security", "tools", "books"], "tier": 3},
 {"repo": "qazbnm456/awesome-web-security", "topics": ["web", "materials"], "tier": 3},
 {"repo": "paragonie/awesome-appsec", "topics": ["appsec", "learning"], "tier": 3},
 {"repo": "infoslack/awesome-web-hacking", "topics": ["web", "hacking"], "tier": 3},
 {"repo": "Eyadkelleh/awesome-skills-security", "topics": ["ai-agent", "payloads"], "tier": 3},
]

GAPS = [
 {"area": "browser-ext", "status": "authored-only", "note": "No public checklist found; cards authored from Chrome MV3 docs. Confidence medium."},
 {"area": "desktop", "status": "authored-only", "note": "No public checklist found; cards authored from Electron security docs. Confidence medium."},
 {"area": "telegram", "status": "authored-only", "note": "No canonical repo; cards authored from Telegram Bot API docs; tosint used for token recon."},
]

def main():
    fd = os.path.join(ROOT, "fixtures"); os.makedirs(fd, exist_ok=True)
    for name, data in FIXTURES.items():
        with open(os.path.join(fd, name + ".yaml"), "w") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)
    os.makedirs(os.path.join(ROOT, "references"), exist_ok=True)
    with open(os.path.join(ROOT, "references", "index.yaml"), "w") as f:
        yaml.safe_dump({"references": REFERENCES, "known_gaps": GAPS}, f, sort_keys=False, allow_unicode=True, width=100)
    print(f"fixtures={len(FIXTURES)} references={len(REFERENCES)} gaps={len(GAPS)}")

if __name__ == "__main__":
    main()
