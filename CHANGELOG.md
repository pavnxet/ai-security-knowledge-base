# Changelog

## [0.9.8] — beta
### Added
- Documented **direct slash-command invocation** of the agent skill (e.g. `/secure-kb-audit ./my-app`),
  with `$ARGUMENTS` handling in the skill body: a path typed after the command is used as the target.
  Frontmatter stays strictly spec-valid (the Claude Code `argument-hint` field is a harness extension
  that the base Agent Skills spec rejects, so argument handling lives in the body instead).

## [0.9.7] — beta
### Added
- **Agent Skill: `skills/secure-kb-audit/`.** A portable Agent Skills bundle (SKILL.md + references +
  assets + scripts) that lets Claude Code, Codex, OpenCode, Pi and any spec-compliant harness audit a
  codebase with the KB. Includes `scripts/install.sh` (symlink/copy into `~/.claude/skills`,
  `~/.agents/skills`, `~/.config/opencode/skills`, `~/.pi/agent/skills`, or project-local paths) and
  `scripts/find_kb.py` to locate the KB.
- `tests/test_skill.py` — validates frontmatter against the spec, that every file SKILL.md references
  exists, and that the locator works.

## [0.9.6] — beta
### Changed
- **Query normalisation + porter stemming.** Queries are stripped of conversational intent ("how do I …") and abbreviations expanded (`sqli` → `sql injection`); the FTS index now uses `tokenize='porter unicode61'`. Query/index-side only — no card refs change, content_hash unchanged.
- Strict recall: all 0.682→**0.695**, curated v1 0.305→**0.339**, v2_dev 0.425→**0.525**; curated v2 0.475 (flat); templated 0.916.
- An external reviewer projected these fixes would reach 0.75/0.64/0.65. **Measured, they do not** — the real gain is ~+0.01/+0.10, not +0.07/+0.22.

## [0.9.5] — beta
### Fixed (found by an independent reviewer)
- UTF-8 on every text `open()` (Windows cp1252 crash); index cache validated (no silent poisoning); order-insensitive `content_hash`.

## [0.9.2] — beta
### Added
- **R1c: official CWE mapping.** Cards now carry CWEs from official sources only — ASVS→CWE,
  OWASP Top 10 per-category CWE lists, API Top 10 per-category lists, CWEs cited in each card's own
  source document, and official CWE-title matches — tagged `cwe_source: mapped`. See `docs/CWE.md`.
- `scripts/cwe_audit.py` — per-rule n + topicality audit, written to `bench/cwe_audit.json`.
### Changed
- Honest effect: held-out all 0.662 → 0.669; curated v2 0.441 → 0.458; v2_dev 0.250 → 0.325;
  fast-gate recall 26.7% → 46.7%. **Targets not met except `templated`.** Corpus 2,057 → 2,052.
### Corrected
- v0.9.3 removed a keyword→CWE table that had been mislabelled `mapped`; it inflated strict metrics
  by relabelling heuristics and adding refs. See `docs/CWE.md` "Correction".

## [0.9.1] — beta
### Added
- **Verifiable Security Attestation (VSA)** — `secure-kb attest` / `verify-attestation`, and the
  `attest` / `verify_attestation` MCP tools. A deterministic, tamper-evident proof binding the check
  list + results + evidence hashes to the KB content hash and the target's exact content
  fingerprint, verifiable offline. See `docs/ATTESTATION.md`.
- 5 unit tests covering attestation round-trip, tamper detection, target-change detection,
  wrong-key rejection, and determinism.

## [0.9.0] — public beta
### Added
- **GitHub Pages site** (`docs/`) — Claude-inspired theme, zero-build static HTML/CSS/JS.
- **Sharded index** — `index/checks/part-001..005.jsonl` (each ≤ 800 KB) for no-build `jq`/`grep`.
- `CITATION.cff`, `RELEASE_CANDIDATE.md`, `PUBLIC_LAUNCH_CHECKLIST.md`, `PROGRESS.md`.
### Changed
- **Source-identity card IDs** (`SKB-<SRC>-<official-id>`) — merges can no longer churn IDs;
  merged members recorded in `aliases[]`.
- **Deterministic, order-independent build** — identical `content_hash` under shuffled input.
- `index/` and `index/kb.sqlite` are **auto-built on first use** (gitignored).
- Internal reports moved to `docs/history/`.
### Known
- Retrieval below target (held-out 0.66, curated v2 0.44, v2_dev 0.25). Published as beta, not v1.0.0.


## v0.2.1 (2026-10-19)

### Phase fixes
- **CWE coverage**: added the ASVS 5.0 CWE mapping (`scripts/ingest/data/asvs_cwe_mapping.json`);
  cards carrying a CWE went **15 -> 89**.
- **Benchmark repair**: 27/59 curated expected refs were invalid (ASVS v4 ids, pre-2023 WSTG codes).
  Added `bench/heldout_queries_v2.yaml` with expectations derived from the *standards text*. Curated
  recall@5: **v1 0.305 -> v2 0.678**.
- **Tool adapters verified**: 4/12 confirmed against their READMEs (gitleaks, trufflehog, semgrep,
  dependency-check); gitleaks command corrected to v8.30 (`dir`/`git`; `detect` deprecated). 8 remain
  `verified: false`.
- **Bug fix**: `phase_d.py` was clobbering profile fingerprints, leaving `index/router.json` empty and
  `detect` broken. Now imports `FINGERPRINTS`; `detect` returns the correct platforms.

### Pre-public hardening
- `staging/` and `legacy/` removed from git (`.gitignore`); regenerating scripts retained.
- Secret scan (gitleaks 8.30.1 + trufflehog 3.99.2, tree + history): all findings are false
  positives (card IDs; a Postgres connection-string placeholder (user:password@host)). **0 real secrets.**
- Added `SECURITY.md`, `CONTRIBUTING.md`, `.gitleaks.toml`, `.trufflehog-exclude.txt`,
  `PRE_PUBLIC_CHECKLIST.md`, and an **Install in 60 seconds** README section + MCP config.
- CI fixed for the v0.2 pipeline and a secret-scan job added.

### Honest benchmark (832 cards)
held-out all recall@5 0.70; curated v1 0.31; curated v2 0.68; templated 0.95. Lab coverage 36.7%;
fast-gate recall 20.0%.

### Still open / unverified
- 8/12 tool adapters unverified; Telegram `secret_token` claim unverified; two project-declared
  licences; acceptance criteria not fully met -> **no release tag yet**.


## v0.2.0 (2026-10-19)

### Content rebuilt from real sources (Phase B)
- **76 hand-written cards → 834 cards**, 819 of them `extraction: programmatic` (parsed from source
  files at pinned commits) + 15 `authored` gap cards.
- New per-source parsers in `scripts/ingest/`; raw items in `staging/*.jsonl` (836 staged items).
- Sources ingested programmatically: ASVS 5.0 (345 requirements, CSV), MASVS (24 controls, YAML),
  MASTG (78 tests across all 7 MASVS groups), WSTG (115 test cases, checklist.json),
  OWASP Top 10 2025 (9), API Security Top 10 (9), LLM Top 10 (9), CheatSheetSeries (169 rule items
  from 21 sheets), smart-contract-vulnerabilities (38), not-so-smart-contracts (11), ISTG (19),
  vibe-security-skill (39).
- Every programmatic card carries `sources[].path + anchor + commit` (real file provenance).

### Every v0.1 card re-classified (Phase A)
- **All 76 v0.1 cards were `from-memory`** (0 programmatic, 0 verified manual-paraphrase) — see
  `AUDIT_v0.1.md`. They are preserved in `legacy/v0.1_checks/` and downgraded to
  `extraction: from-memory`, `verified: false`, `confidence: low`.
- v0.1 IDs still resolve: `index/aliases.json` maps **13** to v0.2 cards; the other **63** resolve
  to the preserved legacy copy (+46 merge-aliases). **No v0.1 ID was dropped**, but only 13/76 map
  to a rebuilt card.

### Licensing (Phase A.3)
- `OWASP/Top10`, `OWASP/owasp-istg` → CC BY-SA 4.0 (LICENSE file read).
- `OWASP/API-Security`, LLM Top 10 → CC BY-SA 4.0 **project-declared, LICENSE unverified**.
- `ConsenSysDiligence/smart-contract-best-practices` → NONE → reference-only; **6 derived cards removed**.
- No card derives text from a NONE-license repo.

### Dedupe (Phase C)
- 50 cards merged into canonical cards (`merged_from` recorded); 165 borderline pairs listed in
  `dedupe_report.md` for human review. 834 cards after merge.

### Priority & retrieval (Phase D)
- Rule-based `priority` (formula in `docs/PRIORITY.md`).
- Gates: `fast` (≤25) / `standard` (≤100) / `full` per platform.
- Shards `index/by_platform/<p>.jsonl` + `index/brief.tsv` for grep fallback.

### Benchmark (Phase E)
- `bench/heldout_queries.yaml` (154 queries, expected = official refs), `bench/labs.yaml`,
  `bench/user_queries.yaml` (slot for 20 owner queries), `bench/results.json`.
- Results (honest): recall@5 = 0.695 (all) / **0.288 (curated)** / 0.947 (templated); lab coverage
  36.7%; fast-gate recall 20.0%. Worst queries and causes in `BUILD_REPORT.md`.

### Schema
- Added `extraction`, `verified`, `corroboration`, `merged_from`, `replaced_by`; `sources[]` gained
  `path`, `anchor`, `extraction`, `verified`.

### Still open
- `fix`/`detect` on standards cards are pointers/heuristics, not extracted remediation.
- Tool adapter commands unverified; Telegram `secret_token` claim unverified.
- Curated benchmark expected refs use ASVS v4 / pre-2023 WSTG codes → understated recall.
