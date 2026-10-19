# AUDIT_v0.1.md — audit of secure-kb v0.1.0

Produced at the Phase A checkpoint. Method: inspect every v0.1 card, its `sources[]`, the source
registry, and the build scripts; verify official docs live; check tool commands against READMEs.
**Nothing below is claimed as "verified" without the count behind it.**

## A.1 Extraction classification of the 76 v0.1 cards

| classification | count |
|---|---|
| `programmatic` (extracted from a source file) | **0** |
| `manual-paraphrase` (traceable to a real file path + heading/line) | **0** |
| `from-memory` | **76** |

Evidence:
- Source entries across all 76 cards that record a `path`: **0** (they carried `repo` + `commit` only).
- The cards were written by hand in `scripts/cards_data_{a,b,c}.py` (present in v0.1), not parsed from any file.

**Conclusion: the independent review was correct.** v0.1 was a hand-written sample, not a merge of the
sources. All 76 cards are therefore downgraded: `extraction: from-memory`, `verified: false`,
`confidence: low`. They are preserved under `legacy/v0.1_checks/` and their IDs remain resolvable via
`index/aliases.json` (see A.5). This is the honest baseline; Phase B replaces the content with
programmatic cards.

## A.2 Provenance (repo-level only)

v0.1 recorded `repo@commit` per card. It did **not** prove which file the text came from. Fixed in
v0.2: every programmatic card records `path` + `anchor` + `commit` (see `sources[].extraction=programmatic`).

## A.3 License table (all 67 sources)

| outcome | count | meaning |
|---|---|---|
| `derive` | 28 | permissive/CC — text may be derived (with attribution) |
| `reference-only` | 15 | NO license / incompatible / archived — mined for links only, **no text derived** |
| `tool-adapter` | 16 | tools — `tools/*.yaml` describe invocation only, no code copied |
| `fixture` | 8 | labs — mapped to check IDs in `fixtures/`, no code copied |

`NONE`/`NOASSERTION` sources (19 at v0.1) were re-checked against their actual LICENSE files where the
repo was fetchable:
- `OWASP/Top10` → **CC BY-SA 4.0** (LICENSE file read) → `derive`
- `OWASP/owasp-istg` → **CC BY-SA 4.0** (LICENSE file read) → `derive`
- `OWASP/API-Security`, `OWASP/…LLM…` → **CC BY-SA 4.0 (project-declared, LICENSE not machine-read** — repos too large to fetch) → `derive`, flagged unverified
- `ConsenSysDiligence/smart-contract-best-practices` → **NONE** (no LICENSE file) → `reference-only`; its 6 derived cards were **dropped**

Cards whose only source is a `reference-only` repo: **0 remaining** (the 6 ConsenSys cards were removed).

## A.4 Authored cards — official-doc verification

| doc | fetched | verified_on | result |
|---|---|---|---|
| Telegram Bot API | yes | 2026-10-19 | reachable; HTTPS requirement + token format confirmed in the excerpt. `secret_token` param **not visible in the fetched excerpt → that specific claim marked unverified** |
| Chrome MV3 "Stay secure" | yes | 2026-10-19 | confirmed: minimal permissions, never HTTP, explicit CSP, avoid document.write/innerHTML, validate content-script messages, restrict externally_connectable |
| Chrome MV3 CSP reference | yes | 2026-10-19 | confirmed CSP guidance |
| Electron Security | yes | 2026-10-19 | confirmed the 20-item checklist incl. contextIsolation, nodeIntegration, sandbox, CSP, webSecurity, validate IPC sender |

So browser-ext and desktop authored cards are doc-verified. Telegram cards are **partially verified**
(the setWebhook `secret_token` detail could not be confirmed from the fetched excerpt).

## A.5 v0.1 → v0.2 ID mapping

`index/aliases.json` contains a key for every v0.1 ID: **13 mapped** to a v0.2 card by title
similarity; the other **63 have no confident match** and resolve to the preserved
`legacy/v0.1_checks/` copy. The file also holds **46 merge-aliases** (merged card id -> canonical id).
No v0.1 ID is silently dropped, but note that only 13/76 map to a rebuilt card — the rest are
resolvable but not re-sourced.

## A.6 Tool adapters

`tools/*.yaml` install/run commands were **not** individually re-verified against each tool's README
at the pinned commit in this pass → status **unverified**. Listed as an open item in BUILD_REPORT.

## A.7 Everything downgraded / changed (log)

1. 76/76 v0.1 cards → `from-memory`, `verified: false`, `confidence: low` (preserved in `legacy/`).
2. 6 cards derived from `ConsenSysDiligence/smart-contract-best-practices` → **removed** (NONE license).
3. `OWASP/Top10`, `OWASP/owasp-istg` license corrected to CC BY-SA 4.0 (was NOASSERTION).
4. `OWASP/API-Security`, `OWASP/…LLM…` license set to CC BY-SA 4.0 **unverified** (flagged).
5. `tools/*.yaml` marked **unverified**.

## A.8 Open / unverified items

- Telegram `secret_token` claim: unverified from fetched excerpt.
- API-Security & LLM Top 10 licenses: project-declared, LICENSE not machine-read.
- Tool adapter commands: unverified against READMEs.
- Benchmark curated expected refs: authored from memory of ASVS v4 / pre-2023 WSTG codes → themselves unverified (see bench results).
