#!/usr/bin/env python3
"""Write tools/<name>.yaml adapters. No vendored code - we only describe how to call."""
import os, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOOLS = [
 dict(name="gitleaks", platforms=["generic","web","api","cloud","vibe"], detects="Hardcoded secrets in working tree and git history",
      install="brew install gitleaks  # or: go install github.com/gitleaks/gitleaks/v8@latest",
      run="gitleaks detect --source . --report-format json --report-path gitleaks.json",
      output_format="json", maps_to=["SKB-GEN-SECRETS-0022","SKB-VIBE-SECRETS-0069","SKB-TG-SECRETS-0033","SKB-MOB-APKSECRETS-0031"],
      license="MIT", source="gitleaks/gitleaks", requires="external-binary"),
 dict(name="trufflehog", platforms=["generic","web","api","cloud"], detects="Leaked credentials with live verification",
      install="brew install trufflehog  # or docker",
      run="trufflehog filesystem . --json > trufflehog.json",
      output_format="jsonl", maps_to=["SKB-GEN-SECRETS-0022"], license="AGPL-3.0", source="trufflesecurity/trufflehog", requires="external-binary"),
 dict(name="ggshield", platforms=["generic"], detects="500+ secret types incl. pre-commit hook",
      install="pip install ggshield",
      run="ggshield secret scan path .",
      output_format="text/json", maps_to=["SKB-GEN-SECRETS-0022"], license="MIT", source="GitGuardian/ggshield", requires="external-binary+token"),
 dict(name="semgrep", platforms=["web","api","cloud","web3","llm","vibe"], detects="Static patterns for injection, XSS, misconfig across many languages",
      install="pip install semgrep",
      run="semgrep --config p/owasp-top-ten --config p/secrets --json -o semgrep.json .",
      output_format="json", maps_to=["SKB-WEB-INJECT-0003","SKB-WEB-XSS-0004","SKB-WEB-DESER-0009","SKB-W3-REENTRANCY-0060","SKB-LLM-INJECT-0065"],
      license="LGPL-2.1", source="semgrep/semgrep", requires="external-binary"),
 dict(name="zaproxy", platforms=["web","api"], detects="Runtime web/API vulnerabilities (DAST): headers, XSS, injection, auth",
      install="docker pull zaproxy/zap-stable",
      run="docker run -t zaproxy/zap-stable zap-baseline.py -t https://TARGET -J zap.json",
      output_format="json", maps_to=["SKB-WEB-HEADERS-0011","SKB-WEB-XSS-0004","SKB-WEB-INJECT-0003","SKB-API-AUTH-0015"],
      license="Apache-2.0", source="zaproxy/zaproxy", requires="external-binary+network"),
 dict(name="dependency-check", platforms=["generic","web","api","cloud"], detects="Vulnerable dependencies (SCA) against CVE/NVD",
      install="brew install dependency-check  # or docker",
      run="dependency-check --project app --scan . --format JSON --out dc.json",
      output_format="json", maps_to=["SKB-GEN-SCA-0023","SKB-VIBE-SLOPSQUAT-0073"], license="Apache-2.0", source="dependency-check/DependencyCheck", requires="external-binary"),
 dict(name="apkleaks", platforms=["android","mobile"], detects="Secrets, URIs and endpoints inside an APK",
      install="pip install apkleaks",
      run="apkleaks -f app.apk -o apkleaks.json",
      output_format="json", maps_to=["SKB-MOB-APKSECRETS-0031"], license="Apache-2.0", source="dwisiswant0/apkleaks", requires="external-binary"),
 dict(name="mobsf", platforms=["mobile","android","ios"], detects="Automated mobile static + dynamic analysis",
      install="docker pull opensecurity/mobile-security-framework-mobsf",
      run="docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
      output_format="json/api", maps_to=["SKB-MOB-STORAGE-0024","SKB-MOB-NETWORK-0026","SKB-AND-COMPONENTS-0027","SKB-AND-WEBVIEW-0029"],
      license="GPL-3.0", source="MobSF/Mobile-Security-Framework-MobSF", requires="external-binary+docker"),
 dict(name="emba", platforms=["iot"], detects="Firmware security analysis (embedded)",
      install="git clone https://github.com/e-m-b-a/emba && cd emba",
      run="./emba -f firmware.bin -l ./logs",
      output_format="html/json", maps_to=["SKB-IOT-SECRETS-0059","SKB-IOT-UPDATE-0057","SKB-IOT-EXPOSURE-0058"],
      license="GPL-3.0", source="e-m-b-a/emba", requires="external-binary+linux"),
 dict(name="helmet", platforms=["web"], detects="Missing/insecure HTTP security headers (Express)",
      install="npm install helmet",
      run="app.use(require('helmet')())  # then verify headers",
      output_format="n/a", maps_to=["SKB-WEB-HEADERS-0011","SKB-WEB-NET-0012"], license="MIT", source="helmetjs/helmet", requires="library"),
 dict(name="secure_headers", platforms=["web"], detects="Security headers with safe defaults (Rails)",
      install="gem install secure_headers",
      run="SecureHeaders::Configuration.default  # then verify headers",
      output_format="n/a", maps_to=["SKB-WEB-HEADERS-0011"], license="MIT", source="github/secure_headers", requires="library"),
 dict(name="tosint", platforms=["telegram"], detects="Telegram bot token exposure recon (defensive)",
      install="pip install -r requirements.txt  # from repo",
      run="python3 tosint.py --token <BOT_TOKEN>",
      output_format="text", maps_to=["SKB-TG-SECRETS-0033"], license="GPL-3.0", source="drego85/tosint", requires="external-script"),
]

def main():
    d = os.path.join(ROOT, "tools")
    os.makedirs(d, exist_ok=True)
    for t in TOOLS:
        with open(os.path.join(d, t["name"] + ".yaml"), "w") as f:
            yaml.safe_dump(t, f, sort_keys=False, allow_unicode=True, width=100)
    print(f"wrote {len(TOOLS)} tool adapters")

if __name__ == "__main__":
    main()
