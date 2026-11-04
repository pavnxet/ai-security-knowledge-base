# Security Audit — hotchpotch/openai-api-server-via-codex (api + llm)

**Scope:** `https://github.com/hotchpotch/openai-api-server-via-codex` at commit
`1d87f332166194c6de5b96ee61106dc58cc9291a` (2026-11-04, "Use Python 3.11 for development and fix
dev dependency alerts (#47)"). All Go runtime code under `cmd/` and `internal/`, the Python
launcher, `Dockerfile` / `docker-compose.yml` / login helper, release scripts under `scripts/`,
and `.github/workflows/`. Target tree fingerprint (secure-kb attestation):
`ae0ad743617b94780ab74f8bfff921cd6dc9a30daff396598b533fcdd2fa8775` (96 files).

**Gate:** `api` / `fast` (25 checks) **and** `llm` / `fast` (10 checks) — 35 gate cards, plus 10
targeted non-gate cards found with `secure-kb search`, and 2 findings with no matching card
(reported as `gap: true`, per `AGENTS.md`).

**Knowledge base:** secure-kb `0.9.16` (`content_hash` `a57da404205eada6`).

**Method:** static review against secure-kb cards, following `skills/secure-kb-audit/SKILL.md`
(detect → gate → check → report → attest). Not a dynamic test or professional audit. The Go
toolchain was not available in the audit sandbox, so the target's test suite was **not** executed;
test code was read as evidence instead (see *Coverage caveats*). No live Codex backend calls were
made. Every gate decision is recorded in [`results.json`](results.json) (validates with `secure-kb report validate`), and two unsigned
verifiable attestations are attached: [`attestation-api.json`](attestation-api.json)
(id `b853a09e…4932e3`) and [`attestation-llm.json`](attestation-llm.json) (id `2b63d54b…4949c`),
both `verify-attestation … --path <clone>` → `VALID` at audit time. An attestation proves what was
claimed against which code/KB build — not that the claims are correct.

> **Platform-detection note.** `secure-kb detect` ranked the target `llm` (187) ≫ `vibe` (58) >
> `web` (22) > `telegram` (21) > `api` (18). Reading the code shows the product is a local
> OpenAI-compatible **HTTP API server** backed by a remote LLM service, so the correct gates are
> `api` + `llm`. The `telegram`/`vibe` scores are fingerprint noise (Python filenames, `AGENTS.md`)
> and were not audited. This is exactly the "detection is a hint" failure mode the skill warns
> about — recorded here so the gate choice is reviewable.

Evidence links below point at the audited commit. Short form `file:line` is used in tables.

---

## Threat model

Filled in **before** assigning any severity. Two deployment contexts from the target's own docs
are assessed, because several checks are only findings in one of them:

- **Context A — default local tool.** One user, loopback bind (`127.0.0.1:18080`), used by local
  OpenAI-SDK apps/scripts.
- **Context B — documented exposed mode.** `--host 0.0.0.0` (README "Protecting the local API"),
  Docker with a published port, or several apps/people sharing one instance and one API key.

| | |
|---|---|
| **Assets** | 1) The Codex/ChatGPT OAuth credential set in `~/.codex/auth.json` — especially the rotating **refresh token** (the crown jewel: account-level access). 2) The in-memory access token and `ChatGPT-Account-ID`. 3) The subscription quota / ChatGPT credits the server spends. 4) Prompts, files/audio and model outputs passing through, including everything retained in the local in-memory stores. 5) The optional incoming `--api-key`. 6) Host availability (RAM/disk/CPU) and other same-user processes the daemon can signal. |
| **Trust boundaries** | (i) HTTP/WebSocket client → server (`/v1/*`, `/healthz`): callers may be local SDK apps, **web pages in the user's browser**, other LAN hosts (Context B). (ii) Server → Codex backend (`https://chatgpt.com/backend-api/codex`) and → token endpoint (`https://auth.openai.com/oauth/token`), where the server presents the owner's credentials — a classic confused-deputy boundary. (iii) Server ↔ local filesystem (`auth.json`, config TOML, daemon state/PID/log dirs, temp files). (iv) Build/release supply chain (Go modules, npm in the login image, GitHub Actions, container base images) → binaries that run next to asset (1). |
| **Assumptions** | Single account owner; the operator is authorised to use that ChatGPT account. Unsandboxed processes running as the **same OS user are trusted** — they can typically read `~/.codex/auth.json` directly, so findings that require same-UID code execution are out of scope unless they cross a privilege/file boundary (noted per finding). Browser origins and other LAN machines are **not** trusted. The upstream Codex/ChatGPT service is trusted but its responses are treated as untrusted *data* for API10 purposes. TLS to upstream is provided by Go's stdlib defaults. |
| **Out of scope** | Security of OpenAI/ChatGPT services themselves; whether this unofficial use of the Codex backend complies with OpenAI's terms (an account/legal risk the repo's own disclaimer flags — not assessed here); downstream applications that consume this API (their prompt-injection/output-handling duties are noted where a card lands there); live/dynamic testing; the host OS and Docker daemon configuration beyond the files in the repo. |

---

## Summary

**Gate result: FAIL** (launch-gate rule: zero critical/high fails). 35 gate cards:
**8 pass · 9 fail · 15 n/a · 3 unknown.** Expanded into **13 assigned-severity findings:
0 Critical · 5 High · 4 Medium · 4 Low** (severities assigned for this app, not inherited from
cards; where a finding is conditional on Context B, that is stated in its heading note).

| Severity | Findings (assigned) | Gate cards failing at this card severity |
|---|---|---|
| Critical | 0 | 2 (`SKB-API-API1-2023`, `SKB-ASVS-V6-1-1` — both reassigned High for this app, see F-05/F-02) |
| High | 5 (F-01…F-05) | 5 |
| Medium | 4 (F-06…F-09) | 2 |
| Low | 4 (F-10…F-13) | — |

**Plain-language verdict.** This is a carefully engineered local tool with unusually good
hygiene for its class — constant-time key comparison, auth preflight before binding, systematic
log redaction, fuzz-tested proxy paths, digest-pinned images, OIDC PyPI publishing. Its security
model nevertheless rests on one load-bearing assumption, *"only my own code can reach
127.0.0.1:18080"*, and that assumption is weaker than the code admits: no `Host`/`Origin`
validation and no `Content-Type` enforcement mean browser-based attackers (cross-origin simple
requests, DNS rebinding) can reach an API that spends the owner's ChatGPT quota and can read
everything in the in-memory stores (F-01). The documented LAN/Docker mode is not fail-closed —
the same server will happily bind `0.0.0.0` with no key, over clear-text HTTP (F-02). Two
one-request denial-of-service holes (unbounded disk spooling in the proxy, an uncapped chat `n`
allocator) sit next to otherwise thoughtful resource limits (F-03, F-04). Fix F-01 and F-02
first; they decide whether every other strength in this codebase actually protects anything.

---

## Findings

### [HIGH] F-01 — No `Host`/`Origin` validation: browsers can drive the "local-only" API (cross-origin requests + DNS rebinding) — `SKB-ASVS-V3-5-1`

**Standard:** `ASVS:V3.5.1`; also `SKB-WSTG-INJT-17` (host header), `SKB-ASVS-V4-4-2`
(WebSocket origin must be checked against an allowlist), and
`SKB-CS-REST-SECURITY-CHEAT-SHEET-VALIDATE-CONTENT-TYPES`. (Targeted cards, not in either fast
gate — found via `secure-kb search`.)

**Evidence:**
- [`internal/app/server.go:192-242`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L192-L242)
  — `serveHTTP` routes solely on path/method and the optional bearer check at line 205. `r.Host`
  and `Origin` are never inspected for HTTP routes (grep: the only `Origin` use in the codebase is
  the WebSocket check below).
- [`internal/app/server.go:971-975`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L971-L975)
  — `decodeObject` parses the body as JSON without requiring `Content-Type: application/json`, so
  a CORS-"simple" request (`text/plain`, no preflight) is accepted exactly like an SDK call.
- [`internal/app/websocket.go:89-95`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/websocket.go#L89-L95)
  — the WebSocket handshake does reject cross-origin browsers, but compares `Origin`'s host to the
  attacker-supplied `Host` header (`u.Host` vs `r.Host`), not to an allowlist. Under DNS
  rebinding both are the attacker's domain, so the check passes.
- Defaults make this reachable: loopback bind with **no incoming key required**
  (`internal/app/config.go:17`, `internal/app/server.go:205`).

**Why it matters:** In Context A the intended boundary is "my local apps only". A malicious web
page the user visits can `fetch('http://127.0.0.1:18080/v1/responses', {method:'POST',
mode:'no-cors', headers:{'Content-Type':'text/plain'}, body: JSON.stringify({input:'…'})})` and
the server will run it against the owner's Codex allowance — the page cannot read the response,
but it can burn quota/credits and trigger image generation or F-04/F-03 payloads. With DNS
rebinding (attacker domain re-resolving to `127.0.0.1`), the same page becomes same-origin and
**can** read: `GET /v1/chat/completions` enumerates stored chats (F-05), responses and their full
input history are retrievable, deletions are possible, and the WebSocket relay opens too.
Exploitability varies by browser (private-network-access controls are rolling out unevenly, DNS
pinning differs), which is precisely why servers must not depend on the browser for this
boundary — and intranet/local-network pages and non-browser local attackers are unaffected by
those controls anyway.

**Fix:** Validate `r.Host` against an allowlist derived from the bind address (loopback IPs /
`localhost` in Context A; an explicit `--allowed-hosts` list in Context B), reject state-changing
requests bearing a cross-origin `Origin`, and require `Content-Type: application/json` (415
otherwise) on the JSON endpoints. Apply the same allowlist to the WebSocket `Origin` check
instead of `r.Host`. All three are cheap, SDK-compatible (SDKs send `Host: 127.0.0.1:18080` and
`application/json`), and testable with the existing contract-test harness.

### [HIGH] F-02 — Exposed deployment is not fail-closed: non-loopback bind allowed with no key, no key-strength or auth throttle, clear-text only — `SKB-API-API2-2023` *(Context B)*

**Standard:** `API2:2023` / `CWE-307`; also `SKB-ASVS-V6-1-1` (`ASVS:V6.1.1`, gate),
`SKB-BASE-10-MISSING-RATE-LIMITING-BRUTE-FORCE`, `SKB-CS-REST-SECURITY-CHEAT-SHEET-API-KEYS`,
`SKB-CS-REST-SECURITY-CHEAT-SHEET-HTTPS` (targeted cards).

**Evidence:**
- [`internal/app/server.go:205`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L205)
  — `if s.cfg.APIKey != "" && !validBearer(...)`: an unset key disables incoming authentication
  entirely, whatever the bind address.
- [`internal/app/config.go:133-135`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/config.go#L133-L135)
  — startup validation checks only numeric ranges (port/timeouts/counts). Nothing rejects or even
  warns on `--host 0.0.0.0` (or `--host ""`, which `net.JoinHostPort` turns into `:18080` = all
  interfaces) without a key, and nothing enforces a minimum key length/entropy.
- [`internal/app/server.go:205-213`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L205-L213)
  — failed keys get an immediate `401`; there is no counter, delay, or backoff, and the
  concurrency slot (`acquireRequest`, lines 275-289) is only taken *after* auth, so guessing is
  not even incidentally throttled. (The comparison itself is constant-time —
  `internal/app/server.go:264-271` — which does nothing against online guessing of a weak key.)
- [`internal/app/server.go:65-70`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L65-L70)
  — plain TCP + `http.Server`; there is no TLS serving option, so a Context-B deployment exposes
  the bearer key, prompts and outputs to LAN sniffing unless the operator adds an out-of-repo
  reverse proxy.
- Example keys in the docs invite weak secrets: `--api-key local-secret`
  ([README.md:296-298](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/README.md#L296-L298)),
  `# api_key = "change-me"` (README.md:566). Foreground `--api-key` also puts the secret in the
  process argument list (`internal/app/config.go:110`); the daemon path carefully avoids this by
  passing it via environment (`internal/app/daemon.go:177-178`), which shows the safer pattern
  was known.
- Docker sharpens the edge: the image sets `OPENAI_VIA_CODEX_HOST=0.0.0.0`
  ([Dockerfile:63-65](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/Dockerfile#L63-L65)).
  `docker-compose.yml:11` publishes on loopback by default (good), but a user running the image
  with a plain `-p 18080:18080` gets an unauthenticated, credentialed LLM proxy on every host
  interface.

**Why it matters:** The README *warns* ("Do not bind to `0.0.0.0` without an incoming API key",
README.md:305-307), but a warning is not a control: the failure mode — one flag or one Docker
port flag between a personal ChatGPT account and the LAN/internet, over HTTP, with a guessable
example key and unlimited guesses — is fully silent. Anyone who reaches it gets F-05/F-07 as
well: stored conversations and the whole upstream backend surface under the owner's account.

**Fix:** Refuse to start on a non-loopback bind without an API key unless an explicit
`--allow-insecure-no-auth` (name it honestly) is given; treat empty host as non-loopback.
Enforce a minimum key length (or generate/print a random key on first run), replace doc examples
with `openssl rand -hex 32`-style guidance, add per-address auth-failure throttling/backoff, and
either add TLS flags or document "terminate TLS in a reverse proxy" as a requirement for
Context B rather than an option.

### [HIGH] F-03 — Fallback-proxy and audio request bodies are spooled to disk with no size limit — `SKB-API-API4-2023`

**Standard:** `API4:2023` / `CWE-400, CWE-770`; identical failure under `SKB-LLM-LLM10-2025`
(`LLM10:2025`).

**Evidence:**
- [`internal/app/backend.go:732-761`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L732-L761)
  — `newReplayBody` buffers 1 MiB in memory, then spills to a temp file with
  `written, err := io.Copy(file, body)` (line 755): **no `LimitReader`, no maximum**. The
  upstream client's timeout does not apply yet — this read happens before the upstream request
  exists (`proxyTo`, lines 697-714).
- Reachable from every unhandled `/v1/*` route
  ([`internal/app/server.go:953-962`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L953-L962))
  and from `POST /v1/audio/transcriptions`, which funnels into the same helper
  ([`internal/app/backend.go:784-786`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L784-L786)).
- Contrast proves inconsistency: JSON endpoints cap bodies at 32 MiB
  (`internal/app/server.go:973`), WebSocket frames at 32 MiB / 128 MiB
  (`internal/app/websocket.go:123-124`), upstream error/refresh bodies at 1 MiB. The one endpoint
  family that writes to *disk* is the one without a cap. Concurrency (default 10 slots) bounds
  the *number* of concurrent spools, not their size — ten "infinite" uploads still fill the disk.

**Why it matters:** Any caller who can reach the API (in Context A that includes F-01's browser
callers; in Context B any LAN host) can fill the host filesystem/`$TMPDIR` volume, taking down
the server and anything else sharing the disk. Side effect: up to arbitrary amounts of request
content (e.g. audio) sit in a `0600` temp file that survives if the process is killed mid-request
(cleanup is `defer`red, `proxyTo` line 701).

**Fix:** Enforce a configurable max body size (default consistent with the 32 MiB JSON cap, or a
larger explicit audio cap) with `http.MaxBytesReader` / a counting `LimitReader` that returns
`413` before spooling, and fail the `io.Copy` past the limit rather than at `ENOSPC`.

### [HIGH] F-04 — Chat Completions `n` is uncapped and used as a memory/output multiplier — `SKB-API-API4-2023`

**Standard:** `API4:2023` / `CWE-400, CWE-770`; also `LLM10:2025`.

**Evidence:**
- [`internal/app/server.go:1074-1080`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L1074-L1080)
  — `chatChoiceCount` clamps only the bottom: `if n < 1 { return 1 }; return n`.
- Non-streaming path: [`internal/app/compat.go:447-450`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/compat.go#L447-L450)
  — `choices := make([]any, n)` then a deep `cloneMap(message)` per choice.
- Streaming path: [`internal/app/server.go:613`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L613)
  stores the count, and
  [`internal/app/server.go:784-795`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L784-L795)
  clones the delta `ChoiceCount` times **for every streamed event**.
- The same codebase caps the analogous images parameter at `1..10`
  ([`internal/app/server.go:1149-1159`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L1149-L1159)) —
  the chat cap is an oversight, not a design choice.

**Why it matters:** A single request with `"n": 100000000` makes the server attempt a
multi-gigabyte allocation of cloned choice objects (and, streaming, multiplies every delta).
Go may panic-recover a `makeslice` failure, but a merely-huge `n` will OOM-kill or swap-thrash
the process first. No upstream cost is needed to trigger the streaming variant beyond the first
event. This is reachable by every unauthenticated Context-A caller (see F-01) and is also an
accident waiting to happen with a buggy client.

**Fix:** Cap `n` (e.g. `1..16`, matching common provider limits) in `chatChoiceCount`, rejecting
out-of-range values with `400` the way `validateImage` already does for images.

### [HIGH] F-05 — No object-level authorisation in the shared stores: any caller can list, read, modify and delete every stored object — `SKB-API-API1-2023` *(whenever >1 principal/app shares the instance)*

**Standard:** `API1:2023` / `CWE-285, CWE-639` (card severity critical; assigned High here
because the documented primary use is a single-principal local tool — see *Accepted risks*).
Also the concrete mechanism behind `SKB-LLM-LLM02-2025` and `SKB-LLM-LLM07-2025` failures.

**Evidence:**
- Stores key objects by id only — no owner/principal field exists
  ([`internal/app/store.go:8-17`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/store.go#L8-L17),
  [`:78-88`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/store.go#L78-L88));
  there is exactly one shared API key to key them to (`internal/app/config.go:34`).
- [`internal/app/server.go:831-840`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L831-L840)
  — `GET /v1/chat/completions` **enumerates every stored chat completion** (id discovery is not
  even necessary), filterable by model/metadata.
- [`internal/app/server.go:842-880`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L842-L880)
  and
  [`internal/app/server.go:429-464`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L429-L464)
  — by id alone, any caller can retrieve, message-list, metadata-**update** and **delete** chats,
  and retrieve/delete responses and fetch their **full effective input history**
  (`input_items`, lines 461-490 — including `system`/`developer` messages: the LLM07 leak).
- [`internal/app/server.go:323-329`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L323-L329)
  — `previous_response_id` silently replays another caller's stored context into a new upstream
  request under the owner's credentials.
- Object ids also appear in the always-on access log path (`internal/app/server.go:138`), and
  locally-minted fallback ids carry only 64 bits of `crypto/rand`
  ([`internal/app/compat.go:75-78`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/compat.go#L75-L78)) —
  adequate against online guessing, but they are bearer capabilities and should be treated (and
  logged) as such.

**Why it matters:** The realistic Context-A wrinkle is *multi-app*, not multi-user: the README's
whole pitch is pointing many tools (scripts, LangChain, LiteLLM, …) at one server. The least
trusted of those tools — or a browser via F-01 — can read and destroy every other tool's stored
conversations, including their system prompts. In Context B (a team sharing one key) this is a
textbook BOLA.

**Fix:** Either (a) introduce principals — multiple named API keys, an `owner` field on stored
objects, and an ownership check on every store route including list and `previous_response_id` —
or (b) keep the single-principal design but *say so in the security section*, and reduce the
blast radius (e.g. make chat listing opt-in, stop logging object ids or log a hash). Option (b)
is honest for this product; what is not safe is the current ambiguity.

### [MEDIUM] F-06 — Responses are retained locally even when the client asks for `store=false`, with no TTL — `SKB-LLM-LLM02-2025`

**Standard:** `LLM02:2025` (sensitive information disclosure); retention aspect of
`SKB-ASVS-V14-1-2`.

**Evidence:**
- [`internal/app/server.go:350`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L350)
  and
  [`:384`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L384)
  — `s.responses.remember(...)` is called unconditionally on every completed response. The
  request's `store` flag is never consulted on this path; `prepareResponse` even *defaults* it
  to `false`
  ([`internal/app/compat.go:148`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/compat.go#L148))
  and the downstream request forces `store=false` upstream
  ([`internal/app/backend.go:297`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L297)) —
  so a client can reasonably believe nothing is stored anywhere, while the full input, output,
  and a duplicated growing context are kept locally.
- The chat path **does** honour the flag
  ([`internal/app/server.go:597-599`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L597-L599),
  `:727-728`), making the Responses behaviour an inconsistency rather than a stated policy.
- [`internal/app/store.go:31-52`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/store.go#L31-L52)
  — eviction is by count only (default 1000, `internal/app/config.go:22`); no timestamp/TTL, so
  a little-used server keeps sensitive prompts in RAM for its whole lifetime, and each entry
  stores the input twice (`EffectiveInput` + `Context`, line 47).

**Why it matters:** `store=false` is the API's explicit privacy opt-out; silently retaining the
data anyway (and exposing it via F-05's routes) breaks client expectations and any data-handling
promise a downstream app makes to *its* users. Retention is also what turns F-01/F-05 from
"use my quota" into "read my history".

**Fix:** Honour an explicit `store=false` on the Responses paths (skip `remember`; document that
`previous_response_id`/retrieve then won't work, as upstream), and add a TTL (and ideally a byte
budget) to both stores alongside the existing count cap.

### [MEDIUM] F-07 — The fallback proxy hands every caller the entire Codex backend under the owner's credentials — `SKB-API-API9-2023`

**Standard:** `API9:2023` (improper inventory management, targeted card); least-privilege
counterpart of `SKB-LLM-LLM06-2025` (the agency here is granted to the *caller*, not the model).

**Evidence:**
- [`internal/app/server.go:239-240`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L239-L240)
  — every unmatched `/v1/*` method/path combination falls through to `s.proxy` (including
  wrong-method calls to real routes, which are proxied instead of `405`).
- [`internal/app/backend.go:691-714`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L691-L714)
  — the caller's method, path, raw query and body are forwarded under
  `https://chatgpt.com/backend-api/codex/…` with the owner's `Authorization: Bearer` and
  `ChatGPT-Account-ID` (headers built at lines 214-216). Only a safe *request-header* allowlist
  is applied (line 708) — the path/method space is unbounded.
- Documented behaviour ("best-effort fallback proxy", README.md:512), so this is a deliberate
  feature whose *scope* is the finding. Path handling itself is exemplary (cleaning + fuzzing,
  see *Verified passing*) — the destination host genuinely cannot be escaped; the issue is
  purely that the tested/documented API is no longer the security boundary.

**Why it matters:** Any caller who passes F-01/F-02's (missing) checks can invoke whatever
current or future endpoints exist under the Codex backend base — file, account or admin-ish
surfaces included — as the account owner, without any of this codebase's validation, redaction
or rate/concurrency semantics beyond the slot. It converts "an OpenAI-compatible chat API" into
"a general-purpose credential relay".

**Fix:** Make the fallback opt-in (`--enable-fallback-proxy`, default off) and/or constrain it to
an allowlist of method+path prefixes the project actually intends to support. At minimum, log
fallback use distinctly so owners can see it.

### [MEDIUM] F-08 — Refreshed credentials and the PID file are written via predictable `*.tmp` names that follow symlinks — `gap: true` (no secure-kb card; CWE-377/CWE-59)

**Standard:** *No card.* `secure-kb cwe 377` and `cwe 59` return `[]` on KB v0.9.16; the closest
card (`SKB-BASE-4-STORAGE-SYMLINK-EXPOSURE`) is about web-exposed storage links, a different
bug. Recorded in `results.json → gaps[]` and assessed from general knowledge (CWE-377 insecure
temporary file, CWE-59 link following), per the KB's evidence rules.

**Evidence:**
- [`internal/app/auth.go:125-129`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/auth.go#L125-L129)
  — `tmp := path + ".tmp"; os.WriteFile(tmp, updated, 0600); os.Rename(tmp, path)` for the
  refreshed `auth.json` (live access + refresh tokens).
- [`internal/app/daemon.go:322-327`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/daemon.go#L322-L327)
  — the identical pattern for the PID file.
- The safe pattern already exists two directories away:
  [`internal/app/backend.go:743`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L743)
  uses `os.CreateTemp` with a random suffix.

**Why it matters:** `os.WriteFile` follows symlinks and only applies `0600` when *creating* the
file. A principal who can write to `~/.codex/` (or the state dir) but not read `auth.json` —
another local user on a multi-user host, a sandboxed helper, a synced-folder adversary — can
pre-plant `auth.json.tmp` as a symlink (server truncates/writes the target as the owner, then
`Rename` replaces `auth.json` with that symlink) or as a world-readable regular file (the
refreshed tokens then inherit the wide mode). Preconditions are narrow in the default
single-user setup — the state dir is created `0700` (`internal/app/daemon.go:157-161`), and a
same-UID attacker is already trusted (threat model) — which is why this is Medium, not High;
but the target file is the crown-jewel asset, and the fix is mechanical.

**Fix:** `os.CreateTemp(filepath.Dir(path), ".auth-*.tmp")`, `Chmod(0600)`, write, rename — for
both sites.

### [MEDIUM] F-09 — Two mutable supply-chain inputs remain: the credential-handling login image installs `@openai/codex@latest`, and Actions are pinned by tag, not commit — `SKB-LLM-LLM03-2025`

**Standard:** `LLM03:2025` (supply chain).

**Evidence:**
- [`Dockerfile:28-32`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/Dockerfile#L28-L32)
  — `ARG CODEX_VERSION=latest` + `npm install -g "@openai/codex@${CODEX_VERSION}"`, no integrity
  pin, in the `login` stage whose whole job is creating `auth.json` on the user's mounted
  `~/.codex` volume (`docker-compose.yml:41-42`). (Runtime stage is *not* affected — it ships
  only the Go binary.) The login helper also bridges its loopback OAuth callback onto
  `0.0.0.0:1456` inside the container (`docker/codex-login-entrypoint.sh:8`); compose publishes
  it on host loopback only (`docker-compose.yml:47`), but co-network containers can reach it
  during the login window.
- [`.github/workflows/ci.yml:42,45,51,56`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/.github/workflows/ci.yml#L42-L60)
  and throughout `release.yml` — actions referenced as full semver **tags** (`actions/checkout@v7.0.1`).
  The project mitigates this seriously: `.github/workflows/actions.lock` records the resolved
  commit (`sha1-…`) per action and `verify-lockfile.yml` re-verifies it. But GitHub executes the
  *tag*, not the lockfile, and the verify workflow triggers on `push: branches:[main]` / PR
  (`verify-lockfile.yml:6-11`) — **not** on the `v*.*.*` tags that run the release workflow
  (`release.yml:3-12`). A moved tag would be caught by the next main-branch verification, after
  a release build could already have executed it.

**Why it matters:** Everything else in this pipeline is pinned the hard way (base images by
digest, `uv sync --locked`, PyPI via OIDC trusted publishing, SBOM + provenance on the
container). These two are the remaining "whatever is current on build day runs next to the
credentials / inside the release" inputs. The login image is the worse of the two because its
output *is* the credential file.

**Fix:** Pin `CODEX_VERSION` to an exact version (bump deliberately; Dependabot cannot do
Docker-ecosystem security updates here, per `.github/dependabot.yml:3-7`, so this is a manual
chore worth a release-checklist line). Reference Actions by full commit SHA with the version in
a comment (Dependabot + the existing lockfile tooling can still maintain them).

### [LOW] F-10 — `stop` signals whatever PID the PID file names, without verifying the process identity — `gap: true` (no secure-kb card)

**Evidence:** [`internal/app/daemon.go:311-320`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/daemon.go#L311-L320)
parses a bare integer; [`internal/app/daemon.go:269-295`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/daemon.go#L269-L295)
then `terminateProcess` → `forceKillProcess` on it; on Windows that is `taskkill /PID … /T`
(process *tree*) ([`internal/app/process_windows.go:20-24`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/process_windows.go#L20-L24)).
Nothing checks that the PID still belongs to this server.

**Why it matters:** Stale-PID reuse (or a tampered PID file in a less-protected custom state dir)
makes `openai-api-server-via-codex stop` kill an unrelated same-user process — a local
availability/integrity foot-gun, mitigated in the default layout by the `0700` state dir and
`0600` PID file (`internal/app/daemon.go:157-162,322-327`). Hence Low.

**Fix:** Record and verify a process fingerprint on stop (executable path + start time, or a
pidfd on Linux) and refuse to signal on mismatch.

### [LOW] F-11 — Remaining resource/upstream-consumption gaps next to the two holes — `SKB-API-API4-2023` / `SKB-API-API10-2023`

**Evidence (each small; together they show the limit model isn't applied uniformly):**
- [`internal/app/server.go:410-425`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L410-L425)
  — `inputTokens` decodes/normalises up to 32 MiB and re-marshals it for estimation **without
  taking a concurrency slot**; the JSON handlers generally decode *before* acquiring one
  (e.g. `createResponse` decodes at line 311, acquires at 337), so slow/large uploads sit
  outside the advertised concurrency bound. The `http.Server` sets only `ReadHeaderTimeout`
  (`internal/app/server.go:70`) — there is no inbound body-read deadline for a slow-drip upload
  (contrast the careful between-events idle timeout on the upstream stream,
  `internal/app/backend.go:459`).
- [`internal/app/backend.go:668`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L668)
  — the models response is JSON-decoded with **no byte limit**, unlike the 1 MiB caps on refresh
  and error bodies (`internal/app/auth.go:174`, `internal/app/backend.go:790`). Upstream is
  trusted, so this is defence-in-depth (the API10 residual), not a live bug.
- Stores bound item *count*, not bytes, and a `previous_response_id` chain duplicates the whole
  history into every successor (`internal/app/store.go:47`), so worst-case retained memory is
  `max_stored_items` × per-item size × chain growth, not the tidy "1000 items" the setting
  suggests.
- An idle WebSocket holds its concurrency slot for the connection's life
  ([`internal/app/websocket.go:136-137`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/websocket.go#L136-L137),
  acknowledged in the 503 message at `server.go:287`): 10 idle sockets starve all HTTP traffic.
  There is a write timeout and an upstream ping, but no downstream idle/absolute lifetime.
- [`internal/app/backend.go:291`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L291)
  — the client's `max_output_tokens` is deleted before forwarding (presumably a Codex
  compatibility requirement), so callers cannot bound per-request output spend through the
  standard field; worth one line in the docs' cost section.

**Fix:** acquire the slot (or a cheaper "parse" slot) before body decode everywhere, add the
missing `LimitReader` in `listModels`, give stores a byte budget, and consider an idle timeout
for downstream WebSockets. None of these needs to block F-03/F-04.

### [LOW] F-12 — Sensitive JSON responses carry no anti-caching header, and `nosniff` is not universal — `SKB-ASVS-V14-3-2`

**Standard:** `ASVS:V14.3.2` (`Cache-Control: no-store`), `SKB-ASVS-V3-4-4` (nosniff on *all*
responses) — targeted cards.

**Evidence:** [`internal/app/server.go:991-994`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L991-L994)
`writeJSON` sets only `Content-Type`; the `X-Content-Type-Options` at
[`internal/app/server.go:218`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/server.go#L218)
is set after `/healthz`, the not-found and the `401` branches have already returned. SSE gets
`Cache-Control: no-cache` (`internal/app/server.go:1041`), stored-completion `GET`s get nothing.

**Why it matters:** Mostly academic for SDK clients on loopback, but a browser or shared proxy
that *does* fetch a stored completion (see F-01) may keep it. One wrapper line fixes both:
set `Cache-Control: no-store` and `nosniff` in the top-level `ServeHTTP` for every response.

### [LOW] F-13 — A custom backend URL may downgrade credential transport to clear-text `http`/`ws` — `SKB-API-API10-2023`

**Standard:** `API10:2023` / `CWE-319`; `SKB-CS-REST-SECURITY-CHEAT-SHEET-HTTPS`.

**Evidence:** [`internal/app/backend.go:841`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L841)
accepts `http` as well as `https`; the bearer token is attached unconditionally
([`internal/app/backend.go:214-216`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L214-L216));
the streaming/models paths concatenate the configured base without any scheme validation at all
([`internal/app/backend.go:468`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L468),
[`:655`](https://github.com/hotchpotch/openai-api-server-via-codex/blob/1d87f332166194c6de5b96ee61106dc58cc9291a/internal/app/backend.go#L655)),
and the WebSocket dial resolves through the same permissive helper (`internal/app/websocket.go:25`).

**Why it matters / why only Low:** The default is `https://chatgpt.com/…`
(`internal/app/config.go:20`), the token-refresh URL is a hard-coded `https` constant
(`internal/app/auth.go:17`), and the backend URL is operator-controlled config (a trusted
input). The residual risk is an operator (or a copied config) pointing the server at a
non-local `http://` endpoint and silently sending a live ChatGPT access token in clear text.

**Fix:** Require `https`/`wss` unless the backend host is loopback (test/fake backends), or warn
loudly at startup when credentials will traverse clear text.

---

## Verified passing

Each row is a positive observation — the control was seen in the code, not inferred from the
absence of a bug. Card ids are gate cards unless marked † (targeted).

| Check | Evidence | What was confirmed |
|---|---|---|
| `SKB-API-API7-2023` (SSRF) | `internal/app/backend.go:814-848`; `internal/app/fuzz_test.go:9-38`; `internal/app/compat.go:318-323` | Local code never fetches a caller-supplied URL (`image_url` is forwarded to upstream as data). Proxy targets are rebuilt from the parsed operator base + a cleaned path (`..`, `\`, control chars rejected); a fuzz test asserts scheme/host can never escape the base. |
| `SKB-ASVS-V1-2-2` (URL building) | `internal/app/backend.go:655` (`url.QueryEscape`), `:844-848` | Dynamic URL parts are escaped/rebuilt, fragments dropped, non-http(s) bases rejected. |
| `SKB-ASVS-V1-2-1` (output encoding) | `internal/app/server.go:991-994,1045-1047` | All generated output goes through `encoding/json`; there is no HTML/XML generation to inject into. |
| `SKB-ASVS-V14-2-1` (no secrets in URLs) | `internal/app/server.go:205,264-271`; `internal/app/backend.go:214-216` | Both the local key and the Codex token travel only in `Authorization` headers; no query-string credential is accepted or emitted. |
| `SKB-ASVS-V7-1-2` (concurrency policy) | `internal/app/config.go:23`; `internal/app/server.go:275-289`; README.md:587-588 | One-account concurrency is capped (default 10) with an explicit `503 + Retry-After`, and the behaviour is documented. |
| `SKB-ASVS-V11-4-1` (approved hashes) | `scripts/build-release-archives.py:127`; `scripts/build-platform-wheels.py:40` | SHA-256 is the only hash used (release checksums, wheel records); no MD5/SHA-1 anywhere. |
| `SKB-BASE-2-PATH-TRAVERSAL-IN-FILE-READS` | `os.ReadFile` sites: `internal/app/auth.go:86`, `internal/app/config.go:245`, `internal/app/daemon.go:312` | Every file read uses an operator-configured path; no request input becomes a filesystem path. |
| `SKB-LLM-LLM05-2025` (output handling) | `internal/app/server.go:991-994,1045-1047`; `internal/app/compat.go:395-450`; exec sites `internal/app/daemon.go:172,217`, `internal/app/process_windows.go:17-24` | Model output and tool calls are only JSON/SSE-encoded and relayed to the client — never executed, rendered, or `eval`uated server-side. (Scope: this server only; see Unknowns.) |
| Auth hardening details (supports `SKB-API-API2-2023` partial) | `internal/app/server.go:54-58` preflight before `net.Listen:65`; `internal/app/server.go:264-271` constant-time compare; `internal/app/backend.go:238-270` single reload-and-retry on upstream 401; `internal/app/auth.go:165-182` refresh to a fixed https endpoint with a 1 MiB response cap; refreshed file mode `0600` (F-08 caveat aside) | When keys/tokens are used, they are handled correctly; startup fails closed on bad Codex auth instead of serving unauthenticated. Incoming `Authorization` is never forwarded upstream — upstream headers are built fresh (`backend.go:214-230`) and the proxy copies only an allowlist (`backend.go:708`). |
| Logging/redaction (supports `SKB-LLM-LLM02-2025` partial) | `internal/app/redaction.go:5-17`; call sites `internal/app/server.go:128,132,138,206-210`; `internal/app/websocket.go:251-302` (exact-secret + field-name scrubbing of WS errors, normal output untouched); `internal/app/server.go:695` logs tool-arg *sizes* only; `internal/app/server.go:74-76` logs `api_key_configured=%t`, never the key | No request/response bodies, prompts or presented credentials are logged. Panics log only the panic type and return a generic 500 (`server.go:130-135`). *Caveat:* redaction is regex-based (`bearer …`, `*_token=`, JWT shape) — an opaque secret echoed in free text without a label would survive, and the verbose `settings.resolved` line prints `backend_base_url` raw (userinfo would leak). Defence-in-depth note, not a finding at these call sites. |
| Resource-limit *pattern* (supports `SKB-API-API4-2023` partial) | 32 MiB JSON cap `server.go:973`; SSE 128 MiB/event `backend.go:25,525-551`; WS read limits `websocket.go:123-124`; images `n≤10` `server.go:1157-1159`; `ReadHeaderTimeout` `server.go:70`; bounded retries with capped `Retry-After` `backend.go:39-43,423-451`; store count caps `store.go:48-51` | The *design* consistently bounds resources; F-03/F-04/F-11 are holes in an otherwise real control, which is why they read as oversights. |
| Upstream-response hygiene (supports `SKB-API-API10-2023` partial) | invalid SSE JSON skipped `backend.go:502-504`; response `status` allowlist `backend.go:601-613`; error bodies capped 1 MiB + message redaction `backend.go:74-110,789-802`; proxy response strips hop-by-hop + `Set-Cookie` `server.go:1049-1061`; WS handshake refuses to surface upstream bodies/errors `websocket.go:66-73` and disables redirects `websocket.go:33` | Untrusted upstream bytes are size-bounded, shape-checked and not echoed raw into errors/logs. |
| Docker/container † (`SKB-BASE-A1383BACF7`) | digest-pinned bases `Dockerfile:4,26,44`; non-root `USER app` `Dockerfile:67`; minimal runtime stage `Dockerfile:44-59`; loopback port publish `docker-compose.yml:11`; `/healthz` healthcheck `Dockerfile:71-73` | The shipped image is close to textbook. Compose lacks `read_only`/`cap_drop`/`no-new-privileges` hardening — a suggestion, not a finding at this threat level. |
| Release/supply-chain controls (supports `SKB-LLM-LLM03-2025` partial) | least-privilege workflow permissions (`ci.yml:10-11`, `release.yml:14-15`, job-scoped raises); PyPI OIDC trusted publishing (`release.yml:147-162`); container `provenance: mode=max` + `sbom: true` (`release.yml:244-245`); release `checksums.txt` generated and verified in CI (`scripts/build-release-archives.py:125-129`, `release.yml:120`); `uv sync --locked` (`ci.yml:140`); only 2 Go runtime deps (`go.mod:5-8`); Python launcher shells out with an argv list, no `shell=True` (`openai_api_server_via_codex/launcher.py:20-28`) | F-09 is the residual, not the norm. |
| Secrets hygiene in repo | targeted grep + manual review; `internal/app/auth.go:18` is the *public* Codex OAuth client id; test tokens are generated fakes (`internal/testutil/testauth/auth.go`) | No committed credentials were found. (Scanner-grade secret scanning — gitleaks over full history — was not run; see caveats.) |
| Checked-and-dismissed: unverified JWT parsing | `internal/app/auth.go:188-210` | `jwtPayload` decodes without signature checks, but it only reads `exp`/`chatgpt_account_id` from the operator's *own* local token file to time a refresh and set a header; the upstream service is the verifier. Forging the local file gains nothing the file's owner doesn't already have. Not a finding; recorded so the dismissal is arguable. |

## Could not verify (unknown)

| Check | Why it couldn't be verified | What the user should check |
|---|---|---|
| `SKB-ASVS-V14-1-1` | Needs context outside the repo: the repo identifies tokens and redaction rules (README.md:263-312) but contains no data inventory/classification for prompts, stored inputs/outputs, audio or images. | Does an out-of-repo data-handling note classify prompt/output data and set handling rules for the local stores? |
| `SKB-ASVS-V14-1-2` | Same: protection/retention requirements per data class (TTL, logging, access) are not documented in-repo (`internal/app/store.go:31-52` implements count-only retention). | Decide retention/TTL and write it down (see F-06); then this becomes verifiable. |
| `SKB-ASVS-V7-1-1` | The server issues no sessions; Codex token lifetimes are external (`internal/app/auth.go:185-186`), and local WebSocket connections have no documented idle/absolute lifetime (`internal/app/websocket.go:136-165`). | Is an unbounded-lifetime local WS acceptable, or should a max session age be set/documented? |
| Runtime behaviour generally | Needs a running system: this audit is static, and the sandbox had no Go toolchain, so `go test ./...`/`go vet`/fuzzers were read but not executed, and no endpoint was probed live. | Run `uv run tox` (or `go test ./... && go vet ./...`) and re-check F-03/F-04 with a local fake backend (`internal/testutil/codexfake`) before/after fixing. |
| `prompt_cache_key` / turn-state sharing | Ambiguous in the code: a caller-supplied `prompt_cache_key` becomes the upstream `session_id`/`x-client-request-id` (`internal/app/backend.go:472`), and WS callers can supply `x-codex-turn-state`/`x-codex-turn-metadata` (`internal/app/websocket.go:43`). Whether upstream associates cache/conversation state with these values cannot be determined statically. | Confirm with upstream behaviour tests that one local caller cannot affect another's cached context via a chosen key — relevant only in the shared-instance case (F-05). |
| Downstream LLM01/05/06 duties | The consuming applications are not in this repo. | Any app pointed at this server still owns prompt-injection defences, output handling and tool-call authorisation. |
| GitHub-side settings | Branch protection, required reviewers and the Dependabot auto-merge gate (`.github/workflows/dependabot-auto-merge.yml` relies on "required status checks") live in repo settings, not in the tree. | Confirm required checks/reviews are actually configured on `main`. |

## Not applicable

Every row: why it does not apply, and what would make it apply.

| Check | Why it does not apply | What would make it apply |
|---|---|---|
| `SKB-ASVS-V1-2-4` (SQL injection) | No database or query language anywhere; state is in-memory maps (`internal/app/store.go`). | Adding any SQL/NoSQL persistence for the stores. |
| `SKB-ASVS-V11-3-1`, `SKB-ASVS-V11-3-2` (ciphers) | The app performs no encryption; only `crypto/subtle` (compare) and `crypto/rand` (ids) are used. Transport crypto is Go stdlib TLS to upstream. | Encrypting stored data locally, or terminating client TLS in-process. |
| `SKB-ASVS-V6-2-1`, `SKB-ASVS-V6-2-2` (passwords) | No user accounts/passwords; one operator API key + borrowed OAuth login. The *analogous* key-strength issue is F-02. | Adding multi-user accounts with passwords. |
| `SKB-ASVS-V3-7-1`, `SKB-ASVS-V3-1-1` (browser tech/docs) | No first-party browser client is served; routes are API-only (`internal/app/server.go:192-242`). | Shipping a web UI from this server. |
| `SKB-ASVS-V3-7-3` (external redirect notice) | The only redirect is the fixed internal `/v1 → /v1/` (`internal/app/server.go:214-216`). | Any user-controlled or off-site redirect. |
| `SKB-ASVS-V7-1-3` (federated sessions) | The server creates no sessions; it refreshes a borrowed OAuth token (`internal/app/auth.go:165-182`). | Becoming an identity/session provider for its clients. |
| `SKB-BASE-13-PATH-TRAVERSAL-IN-FILE-SEND` | No file-send/static route exists. | Serving uploaded/generated files from disk. |
| `SKB-LLM-LLM01-2025` (prompt injection) | Inside this server there is no second, less-trusted content channel: one API caller supplies both instructions and input, and nothing is browsed, retrieved or executed server-side. The server even keeps its own injected instruction separate from user text (`internal/app/server.go:1229-1246`, image flow). | The server itself fetching documents/URLs into prompts, or executing model-proposed tools. Downstream apps live with this risk today (see Unknowns). |
| `SKB-LLM-LLM04-2025` (poisoning) | No training/fine-tuning/embedding data is managed. | Adding fine-tuning or a local corpus. |
| `SKB-LLM-LLM06-2025` (excessive agency) | The *model* is granted no server-side agency: tool calls are relayed to the API client (`internal/app/compat.go:395-450`). The real agency problem is caller→backend, filed as F-07 under API9. | Server-side tool/plugin execution on model request. |
| `SKB-LLM-LLM08-2025` (vector/embedding) | No embeddings/vector store/RAG; README states embeddings have no implemented endpoint. | Adding a RAG/vector feature. |
| `SKB-LLM-LLM09-2025` (misinformation) | Transport only — no presentation, citation or truth claim is made to an end user by this code. | A user-facing surface that presents model output as fact. |

## Accepted risks

Risks the audit is *choosing* not to demand fixes for — each states who it is acceptable for.

| Check / finding | Why it is accepted | Acceptable for | **Not** acceptable for |
|---|---|---|---|
| `SKB-API-API1-2023` (F-05, no per-object owners) | The product's invariant is "one owner, one borrowed account"; per-principal authz is meaningless until a second principal exists. The fix demanded is honesty + blast-radius reduction, not a tenancy rewrite. | A single user pointing their own tools at their own server on loopback. | Any shared/team instance, or one reachable by less-trusted local apps — then F-05 must be fixed properly (option (a)). |
| Unauthenticated `GET /healthz` (`internal/app/server.go:193-200`, relied on by `Dockerfile:71-73`) | Returns only `{"status":"ok"}`; container healthchecks need an unauthenticated probe. It does fingerprint the service to anyone who can reach the port. | Loopback and container-network deployments. | Internet-facing exposure (already excluded by F-02). |
| Dependabot security-update auto-merge (`.github/workflows/dependabot-auto-merge.yml`, `.github/dependabot.yml:3-7`) | Scoped to `dependabot[bot]` security updates only, squash-merged only after required checks; the alternative (slow human merges) leaves known-vulnerable deps in place longer. Residual risk: a malicious/compromised "security" release that passes tests merges without human review. | A small project that prefers fast patching and keeps required checks meaningful. | Projects whose threat model includes maintainer-account/dependency compromise at release time. Could not verify the branch-protection settings themselves (Unknowns). |
| Sending all prompt/output data to the ChatGPT/Codex backend (`internal/app/backend.go:468,655`) | That is the product. No local PII filtering is attempted, and upstream retention is OpenAI's policy, not this code's. | Users who understand their prompts leave the machine under their ChatGPT account's terms. | Regulated/confidential workloads assuming "local server = local processing". The README disclaimer should stay prominent. |

## Coverage caveats

- Retrieval is beta (held-out recall@5 ≈ 0.70); a `search` that returns nothing does not prove a
  class is absent — the gate lists above are the authoritative checklist, and the two no-card
  findings (F-08, F-10) are flagged `gap: true` rather than force-matched to a card.
- Detection is heuristic; platform mis-detection is possible. Mitigated here by reading the code
  and auditing `api` + `llm` instead of the raw top hit (see the note under *Method*).
- This is a static review. Anything requiring a running system (auth flows, rate limits, headers
  at runtime) is marked `unknown`, not `pass`. Specifically: **the Go toolchain was unavailable
  in the audit sandbox, so `go test`/`go vet`, the fuzz targets, and any scanner (gitleaks,
  govulncheck, semgrep) were not executed**; CI configuration and test sources were reviewed
  instead. No live Codex credentials were used and no upstream calls were made.
- Card `fix` fields are pointers to the source standards (per `KNOWN_LIMITATIONS.md`); the fixes
  above are the auditor's concrete instantiations for this codebase.
- Ecosystem note for reproducing this audit: `secure-kb profile`/`attest` import `yaml`
  (`cli/secure_kb.py:176`) — with a bare stdlib-only Python they fail until PyYAML (the `dev`/
  `build` extra) is installed. Recorded here so the next auditor isn't surprised; it does not
  affect any result.

---

## Appendix A — Gate matrix (35 cards)

Full evidence strings are in [`results.json`](results.json); this table is the human index.
Card severity is the KB default; finding severity (where different) is in the finding text.

| # | Check | Card sev. | Result | Finding |
|---|---|---|---|---|
| 1 | `SKB-API-API1-2023` Broken object-level authorization | critical | **fail** | F-05 |
| 2 | `SKB-ASVS-V1-2-4` Parameterised queries | critical | n/a | — |
| 3 | `SKB-API-API10-2023` Unsafe consumption of APIs | high | **fail** (residual) | F-11, F-13 |
| 4 | `SKB-ASVS-V1-2-1` Output encoding | critical | pass | — |
| 5 | `SKB-ASVS-V1-2-2` URL encoding | critical | pass | — |
| 6 | `SKB-ASVS-V11-3-1` No weak block modes | critical | n/a | — |
| 7 | `SKB-ASVS-V11-3-2` Approved ciphers | critical | n/a | — |
| 8 | `SKB-ASVS-V11-4-1` Approved hashes | critical | pass | — |
| 9 | `SKB-ASVS-V6-1-1` Auth rate-limit documentation | critical | **fail** | F-02 |
| 10 | `SKB-ASVS-V6-2-1` Password length | critical | n/a | — |
| 11 | `SKB-ASVS-V6-2-2` Password change | critical | n/a | — |
| 12 | `SKB-API-API4-2023` Unrestricted resource consumption | medium | **fail** | F-03, F-04, F-11 |
| 13 | `SKB-API-API7-2023` SSRF | medium | pass | — (see F-07 note) |
| 14 | `SKB-ASVS-V3-7-1` Supported client tech | high | n/a | — |
| 15 | `SKB-ASVS-V3-7-3` External redirect notice | high | n/a | — |
| 16 | `SKB-API-API2-2023` Broken authentication | medium | **fail** | F-02 |
| 17 | `SKB-ASVS-V14-1-1` Data classification | high | unknown | — |
| 18 | `SKB-ASVS-V14-1-2` Data-protection requirements | high | unknown | — (F-06 related) |
| 19 | `SKB-ASVS-V14-2-1` No sensitive data in URLs | high | pass | — |
| 20 | `SKB-ASVS-V3-1-1` Browser security docs | high | n/a | — |
| 21 | `SKB-ASVS-V7-1-1` Session lifetime documentation | high | unknown | — |
| 22 | `SKB-ASVS-V7-1-2` Concurrent session policy | high | pass | — |
| 23 | `SKB-ASVS-V7-1-3` Federated session documentation | high | n/a | — |
| 24 | `SKB-BASE-13-PATH-TRAVERSAL-IN-FILE-SEND` | high | n/a | — |
| 25 | `SKB-BASE-2-PATH-TRAVERSAL-IN-FILE-READS` | high | pass | — |
| 26 | `SKB-LLM-LLM01-2025` Prompt injection | critical | n/a | — (downstream) |
| 27 | `SKB-LLM-LLM10-2025` Unbounded consumption | high | **fail** | F-03, F-04, F-11 |
| 28 | `SKB-LLM-LLM02-2025` Sensitive information disclosure | high | **fail** | F-05, F-06 |
| 29 | `SKB-LLM-LLM03-2025` Supply chain | high | **fail** (residual) | F-09 |
| 30 | `SKB-LLM-LLM04-2025` Data/model poisoning | high | n/a | — |
| 31 | `SKB-LLM-LLM05-2025` Improper output handling | high | pass | — (server scope) |
| 32 | `SKB-LLM-LLM06-2025` Excessive agency | high | n/a | — (see F-07) |
| 33 | `SKB-LLM-LLM07-2025` System prompt leakage | high | **fail** (shared use) | F-05 |
| 34 | `SKB-LLM-LLM08-2025` Vector/embedding weaknesses | high | n/a | — |
| 35 | `SKB-LLM-LLM09-2025` Misinformation | high | n/a | — |

Targeted non-gate cards assessed (all fail, each folded into a finding):
`SKB-ASVS-V3-5-1`, `SKB-CS-REST-SECURITY-CHEAT-SHEET-VALIDATE-CONTENT-TYPES`, `SKB-ASVS-V4-4-2`,
`SKB-WSTG-INJT-17` (F-01); `SKB-CS-REST-SECURITY-CHEAT-SHEET-API-KEYS`,
`SKB-CS-REST-SECURITY-CHEAT-SHEET-HTTPS`, `SKB-BASE-10-MISSING-RATE-LIMITING-BRUTE-FORCE` (F-02);
`SKB-API-API9-2023` (F-07); `SKB-ASVS-V14-3-2`, `SKB-ASVS-V3-4-4` (F-12). Details in
`results.json → targeted_extra_results[]`.

## Appendix B — Suggested fix order

1. **F-01** — `Host` allowlist + `Origin`/content-type enforcement (protects the default install).
2. **F-04, F-03** — cap chat `n`; cap proxy/audio bodies (both are a few lines, both are
   one-request kills).
3. **F-02** — fail closed on non-loopback binds; key strength + auth throttling; TLS story.
4. **F-06** — honour `store=false`; add store TTL. Shrinks F-05's blast radius for free.
5. **F-05 (option b), F-07** — document single-principal-only; make chat listing and the
   fallback proxy opt-in.
6. **F-08, F-09, F-10…F-13** — the mechanical tail: `CreateTemp`, pin the login `CODEX_VERSION`
   and Actions by SHA, PID identity check, `no-store`/`nosniff` wrapper, https-only backend
   (loopback excepted), and the F-11 limit clean-ups.

## Appendix C — Reproduced with

```bash
git clone https://github.com/hotchpotch/openai-api-server-via-codex
cd openai-api-server-via-codex && git checkout 1d87f332166194c6de5b96ee61106dc58cc9291a

KB=/path/to/ai-security-knowledge-base           # secure-kb 0.9.16, content_hash a57da404205eada6
python3 "$KB/cli/secure_kb.py" detect ./openai-api-server-via-codex
python3 "$KB/cli/secure_kb.py" profile api --gate fast --format brief
python3 "$KB/cli/secure_kb.py" profile llm --gate fast --format brief
# … per-check investigation (grep + read), results recorded in results.json …
python3 "$KB/cli/secure_kb.py" report validate audits/openai-api-server-via-codex/results.json
python3 "$KB/cli/secure_kb.py" attest ./openai-api-server-via-codex --profile api --gate fast \
    --results audits/openai-api-server-via-codex/results.json \
    --out audits/openai-api-server-via-codex/attestation-api.json
python3 "$KB/cli/secure_kb.py" attest ./openai-api-server-via-codex --profile llm --gate fast \
    --results audits/openai-api-server-via-codex/results.json \
    --out audits/openai-api-server-via-codex/attestation-llm.json
python3 "$KB/cli/secure_kb.py" verify-attestation audits/openai-api-server-via-codex/attestation-api.json \
    --path ./openai-api-server-via-codex        # -> VALID (unsigned: no --key was used)
```
