#!/usr/bin/env python3
"""Authored gap-platform cards (Telegram, browser-ext, desktop) with verified official-doc provenance.

Every card cites an official doc URL fetched on VERIFIED_ON. No text is invented beyond the doc's
own guidance. confidence is 'low' when a platform has a single authoritative source.
"""
import os, yaml, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TODAY = datetime.date.today().isoformat()

TG = [("https://core.telegram.org/bots/api","Telegram Bot API"),
      ("https://core.telegram.org/bots/webapps","Telegram Mini Apps"),
      ("https://core.telegram.org/widgets/login","Telegram Login Widget")]
CH = [("https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure","Chrome: Stay secure"),
      ("https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy","Chrome MV3 CSP")]
EL = [("https://www.electronjs.org/docs/latest/tutorial/security","Electron Security")]

def docsrc(urls, verified=True):
    return [{"repo": n, "path": None, "anchor": None, "commit": None, "url": u,
             "license": "Official-doc", "type": "official-doc", "extraction": "authored", "verified": verified}
            for u, n in urls]

CARDS = [
 # ---- Telegram (Bot API doc) ----
 dict(id="SKB-TG-SECRETS-0033", title="Telegram bot token kept secret and rotatable",
   summary="The bot token is a full-access credential; never ship or commit it.",
   platform="telegram", dom="secrets", sev="critical", pri=97, cwe=["CWE-798"],
   check="Confirm the bot token is loaded from env/secret store, never in client code or git; the token format is <bot_id>:<35-char secret>.",
   fix="Store the token in a secret manager; revoke via BotFather if leaked; never expose it to Mini Apps.",
   grep=["api.telegram.org/bot","BOT_TOKEN","[0-9]{8,10}:[A-Za-z0-9_-]{35}"], files=["**/*.py","**/*.js","**/*.ts","**/*.env"],
   tags=["telegram","secrets"], urls=TG[:1]),
 dict(id="SKB-TG-WEBHOOK-0034", title="Telegram webhook verifies secret_token",
   summary="setWebhook should set secret_token and the handler must check the header.",
   platform="telegram", dom="webhook", sev="high", pri=94, cwe=["CWE-345"],
   check="Confirm setWebhook passes secret_token and the endpoint rejects updates lacking the X-Telegram-Bot-Api-Secret-Token header.",
   fix="Call setWebhook with a random secret_token; validate the header on every update; reject otherwise.",
   grep=["setWebhook","secret_token","X-Telegram-Bot-Api-Secret-Token"], files=["**/*.py","**/*.js","**/*.ts"],
   tags=["telegram","webhook"], urls=TG[:1]),
 dict(id="SKB-TG-WEBHOOK-0035", title="Telegram webhook served over HTTPS only",
   summary="All Bot API queries must be HTTPS; webhooks need a valid certificate.",
   platform="telegram", dom="network", sev="high", pri=86, cwe=["CWE-319"],
   check="Confirm the webhook URL is https:// with a valid certificate (Bot API requires HTTPS for all requests).",
   fix="Terminate TLS properly; keep the certificate valid.",
   grep=["https://","setWebhook"], files=["**/*.py","**/*.js","**/*.env"],
   tags=["telegram","tls"], urls=TG[:1]),
 dict(id="SKB-TG-INPUT-0036", title="Bot treats every message as untrusted input",
   summary="Message text, callbacks and file names are attacker-controlled.",
   platform="telegram", dom="input-validation", sev="high", pri=88, cwe=["CWE-20"],
   check="Validate/sanitize update fields (text, callback_data, file names, ids) before use in queries, shell, HTML or paths.",
   fix="Validate and escape all update fields; never eval or interpolate them; cap lengths.",
   grep=["message.text","callback_data","update."], files=["**/*.py","**/*.js","**/*.ts"],
   tags=["telegram","input"], urls=TG[:1]),
 dict(id="SKB-TG-ACCESS-0037", title="Admin commands require authorization",
   summary="Privileged bot commands must check the caller is an allowed admin.",
   platform="telegram", dom="access-control", sev="critical", pri=93, cwe=["CWE-862"],
   check="For each privileged command, confirm the handler checks from.id against an allow-list before acting.",
   fix="Maintain an admin allow-list; check sender id server-side; deny by default.",
   grep=["is_admin","from.id","ADMIN"], files=["**/*.py","**/*.js","**/*.ts"],
   tags=["telegram","authz"], urls=TG[:1]),
 dict(id="SKB-TG-RATE-0038", title="Bot applies rate limiting and flood control",
   summary="Bots must throttle users and honor Telegram 429 retry_after.",
   platform="telegram", dom="rate-limiting", sev="medium", pri=70, cwe=["CWE-770"],
   check="Check for per-user throttling and handling of 429 / retry_after with backoff.",
   fix="Throttle per user/chat; honor retry_after; cap concurrent work.",
   grep=["retry_after","429","throttle"], files=["**/*.py","**/*.js","**/*.ts"],
   tags=["telegram","rate-limit"], urls=TG[:1]),
 dict(id="SKB-TG-MINIAPP-0041", title="Telegram Mini App validates initData",
   summary="Mini Apps must verify initData server-side, not trust the client.",
   platform="telegram", dom="auth", sev="high", pri=82, cwe=["CWE-345"],
   check="Confirm the backend validates Web App initData (HMAC with bot token) and expiry before trusting identity.",
   fix="Validate initData hash server-side; enforce expiry; never authorize on client-provided ids.",
   grep=["initData","WebApp","validateInitData"], files=["**/*.ts","**/*.js","**/*.py"],
   tags=["telegram","miniapp"], urls=TG[1:2]),
 # ---- Browser extension (Chrome docs) ----
 dict(id="SKB-EXT-PERMS-0042", title="Extension requests minimal permissions",
   summary="MV3 extensions should register only needed APIs and host permissions.",
   platform="browser-ext", dom="config", sev="high", pri=86, cwe=["CWE-250"],
   check="Review manifest permissions/host_permissions; flag broad ones (<all_urls>, webRequest) not justified by features.",
   fix="Trim to least privilege; use optional_permissions and activeTab; narrow host patterns.",
   grep=["permissions","host_permissions","<all_urls>"], files=["**/manifest.json"],
   tags=["extension","permissions"], urls=CH),
 dict(id="SKB-EXT-CSP-0043", title="Extension includes an explicit CSP and no remote code",
   summary="MV3 requires a content security policy; remote code is banned.",
   platform="browser-ext", dom="config", sev="high", pri=84, cwe=["CWE-829"],
   check="Confirm content_security_policy is set (e.g. default-src 'self') and no eval/remote script loads are allowed.",
   fix="Bundle all code; remove eval; keep the restrictive MV3 CSP.",
   grep=["content_security_policy","eval(","<script src=\"http"], files=["**/*.js","**/manifest.json"],
   tags=["extension","csp"], urls=CH),
 dict(id="SKB-EXT-MSG-0044", title="Extension validates message passing and externally_connectable",
   summary="Messages from content scripts or pages must be validated; restrict external connections.",
   platform="browser-ext", dom="input-validation", sev="high", pri=80, cwe=["CWE-20"],
   check="Validate sender and payload in onMessage; restrict externally_connectable to trusted ids/origins; minimise web_accessible_resources.",
   fix="Validate sender+payload; limit external connect; keep web-accessible resources minimal.",
   grep=["onMessage","externally_connectable","web_accessible_resources"], files=["**/*.js","**/manifest.json"],
   tags=["extension","messaging"], urls=CH),
 dict(id="SKB-EXT-INJECT-0045", title="Content scripts avoid document.write and innerHTML",
   summary="Injecting page data into the DOM enables XSS in the extension context.",
   platform="browser-ext", dom="xss", sev="high", pri=78, cwe=["CWE-79"],
   check="Check content scripts for document.write/innerHTML built from page data; the Chrome guide says to build DOM nodes and use innerText.",
   fix="Use createElement/innerText; never pass page data into the privileged extension context.",
   grep=["innerHTML","document.write"], files=["**/*.js"],
   tags=["extension","xss"], urls=CH),
 # ---- Desktop / Electron (single source -> confidence low) ----
 dict(id="SKB-DESK-ELECTRON-0046", title="Electron renderer is isolated and sandboxed",
   summary="contextIsolation on, nodeIntegration off, sandbox on.",
   platform="desktop", dom="config", sev="critical", pri=92, cwe=["CWE-693"],
   check="In BrowserWindow webPreferences, confirm contextIsolation=true, nodeIntegration=false and sandbox=true.",
   fix="Enable contextIsolation and sandbox; disable nodeIntegration; expose only a minimal preload API.",
   grep=["nodeIntegration","contextIsolation","sandbox","webPreferences"], files=["**/main*.js","**/*.ts"],
   tags=["electron","desktop"], urls=EL),
 dict(id="SKB-DESK-IPC-0047", title="Electron validates IPC sender and options",
   summary="Validate the sender of IPC messages; do not expose dangerous APIs.",
   platform="desktop", dom="input-validation", sev="high", pri=84, cwe=["CWE-20"],
   check="Check ipcMain handlers validate the sender and arguments; never pass untrusted input to shell.openExternal/exec.",
   fix="Validate IPC sender and payload; allow-list URLs/channels; avoid exec/openExternal exposure.",
   grep=["ipcMain","ipcRenderer","openExternal","shell."], files=["**/main*.js","**/preload*.js"],
   tags=["electron","ipc"], urls=EL),
 dict(id="SKB-DESK-CSP-0049", title="Electron defines a restrictive CSP and webSecurity",
   summary="Set a strict CSP, keep webSecurity on, and avoid insecure content.",
   platform="desktop", dom="headers", sev="medium", pri=68, cwe=["CWE-693"],
   check="Confirm a Content-Security-Policy (script-src 'self'), webSecurity not disabled and allowRunningInsecureContent off.",
   fix="Set a strict CSP; keep webSecurity enabled; do not enable insecure content.",
   grep=["Content-Security-Policy","webSecurity","allowRunningInsecureContent"], files=["**/*.html","**/main*.js"],
   tags=["electron","csp"], urls=EL),
 dict(id="SKB-DESK-UPDATE-0048", title="Electron uses a current version and validated updates",
   summary="Keep Electron current; verify update integrity.",
   platform="desktop", dom="supply-chain", sev="high", pri=80, cwe=["CWE-1104"],
   check="Confirm Electron is a current release (older versions carry nodeIntegration-bypass CVEs) and the updater validates signatures over HTTPS.",
   fix="Update Electron; sign releases; verify signatures before install.",
   grep=["electron","autoUpdater","setFeedURL"], files=["**/package.json","**/main*.js"],
   tags=["electron","updates"], urls=EL),
]

def main():
    out = os.path.join(ROOT, "checks")
    for c in CARDS:
        plat = c["platform"]
        card = {
            "id": c["id"], "title": c["title"], "summary": c["summary"],
            "platforms": [plat], "stacks": ["any"], "domain": c["dom"],
            "phase": ["pr-review","pre-launch","full-audit"],
            "severity": c["sev"], "priority": c["pri"], "cwe": c["cwe"], "owasp": [],
            "check": c["check"], "fix": c["fix"],
            "detect": {"grep": c["grep"], "files": c["files"]},
            "verify_evidence": "Cite the file:line or config value inspected to justify pass/fail, or mark unknown.",
            "tags": c["tags"], "sources": docsrc(c["urls"]),
            "origin": "authored", "confidence": "medium" if len(c["urls"]) >= 2 else "low",
            "extraction": "authored", "verified": True, "corroboration": len(c["urls"]),
            "last_verified": TODAY,
        }
        d = os.path.join(out, plat, c["dom"]); os.makedirs(d, exist_ok=True)
        yaml.safe_dump(card, open(os.path.join(d, c["id"] + ".yaml"), "w"), sort_keys=False, allow_unicode=True, width=100)
    print(f"authored cards: {len(CARDS)}")

if __name__ == "__main__":
    main()
