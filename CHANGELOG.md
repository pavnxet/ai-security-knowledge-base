# Changelog

## [0.9.17] — beta
### Added (harness Phase A — machine-checked audit output)
- **`audit/report-schema.json`** — the output contract for an audit, adopting the three-verdict model
  from `cloudflare/security-audit-skill` and extending it with `card_id` and `kb` so every record is
  bound to the corpus that motivated it. A `confirmed` record needs an
  `entrypoint → propagation → sink` trace; `needs_validation` **may not carry a severity** (an
  unproven issue has no impact to rate); `rejected` must carry a reason.
- **`scripts/validate_findings.py`** — zero-dependency validator that interprets the schema directly,
  so the schema stays the single source of truth. Adds two semantic rules the shape cannot express:
  a `confirmed` trace must actually reach a `sink`, and fingerprints must be unique.
- **`audit/findings.example.json`** — a golden fixture with one record of each verdict.
- `tests/test_findings_schema.py` (14 tests) — one per rejection rule, so the validator is proven to
  fail for the right reasons.
- CI step + a new `verify_release.py` check (10 checks now).

### Why
A prose report cannot be deduplicated, re-verified or compared across runs. Three mistakes are easy
to make and hard to see in prose: a "confirmed" claim whose trace never reaches a sink, a severity on
an unvalidated candidate, and a rejection with no reason. All three are now build failures.

## [0.9.17] — beta
### Added (harness Phase A — machine-checked audit output)
- **`audit/report-schema.json`** — the output contract for an audit, adopting the three-verdict model
  from `cloudflare/security-audit-skill` and extending it with `card_id` and `kb` so every record is
  bound to the corpus that motivated it. A `confirmed` record needs an
  `entrypoint → propagation → sink` trace; `needs_validation` **may not carry a severity** (an
  unproven issue has no impact to rate); `rejected` must carry a reason.
- **`scripts/validate_findings.py`** — zero-dependency validator that interprets the schema directly,
  so the schema stays the single source of truth. Adds two semantic rules the shape cannot express:
  a `confirmed` trace must actually reach a `sink`, and fingerprints must be unique.
- **`audit/findings.example.json`** — a golden fixture with one record of each verdict.
- `tests/test_findings_schema.py` (14 tests) — one per rejection rule, so the validator is proven to
  fail for the right reasons.
- CI step + a new `verify_release.py` check (10 checks now).

### Why
A prose report cannot be deduplicated, re-verified or compared across runs. Three mistakes are easy
to make and hard to see in prose: a "confirmed" claim whose trace never reaches a sink, a severity on
an unvalidated candidate, and a rejection with no reason. All three are now build failures.

## [0.9.16] — beta
### Added (Phase 7 — final verification)
- **`scripts/verify_release.py`** — one command that answers "is this release internally
  coherent?": version agreement across VERSION / pyproject / both manifests / README, card counts
  across manifest and `checks/`, `content_hash` agreement, shard ids vs card ids, `kb.sqlite` not
  committed, posture docs present and linked from all three front doors, skill frontmatter valid,
  and the advertised MCP tool lists. Each check maps to a drift that actually happened here.
- `tests/test_release.py` (13 tests) — asserts the verifier passes **and** that it detects a phantom
  shard card, a version mismatch and a hash mismatch, so it cannot become a check that always says ok.
- CI: a `verify_release.py` step in `quality-gates`.

### Fixed
- **The shipped `index/checks/part-*.jsonl` shards were stale.** They carried **2,057 records for
  2,052 cards** — five phantom cards that no longer existed, returned by the zero-install `jq`/`grep`
  fallback documented in `AGENTS.md`. Nothing generated them; they were hand-maintained. The build
  now writes them from the cards and deletes stale parts, so they cannot drift again.
- **README still advertised v0.9.12** after six releases. Now checked by the verifier.

## [0.9.15] — beta
### Changed (Phase 6 — make the posture discoverable)
- **`AGENTS.md` and `llms.txt` now link the whole posture** — threat model, risk register, known
  limitations, SECURITY.md. These are the files an agent reads first, and they linked none of them.
  `AGENTS.md` also gains the two rules that follow: an `accepted` risk is a **decision, not an
  oversight** (don't re-report it; challenge it by ID), and a `search` that returns nothing does not
  prove a class is absent.
- **README gains a consolidated "Security posture" section** — a four-row table of what each document
  settles, instead of the links being scattered across Security and Known limitations.
- **The website gains a "Security posture" section** and its limitations cards are corrected: they
  still claimed official-source CWE enrichment was unimplemented (shipped in 0.9.6) and quoted a
  ~19 s cold build.

### Fixed
- **Stale MCP tool lists.** `AGENTS.md` and `llms.txt` advertised 7 tools; the server exposes **9**
  (`attest` and `verify_attestation` were missing). Both corrected, and a test now compares the
  advertised list against `mcp/server.py` so it cannot drift again.

### Added
- 6 tests in `tests/test_docs.py`: every front door must link all four posture documents; README must
  have a consolidated section; the site must surface the posture; and the advertised MCP tool list
  must equal the real one.

## [0.9.14] — beta
### Changed (Phase 5 — teach the skill to dismiss a finding properly)
- **The report template now opens with a threat model block** — assets, trust boundaries,
  assumptions, out of scope — *before* any finding. Two equally true checks can have opposite
  severities depending on whether the target is a single-user tool or a multi-tenant service; the
  block is what makes the severity call reviewable.
- **Every dismissal now carries a reason.** An `n/a` row must state why it does not apply **and what
  would make it apply**; an accepted risk must state who it is acceptable for **and who it would not
  be**. A dismissal nobody can argue with is indistinguishable from an oversight.
- `references/reporting.md` gains **"Dismissing a finding"** with a worked strong-vs-weak example:
  the strong one argues from the code's own invariant and names the assumption it rests on; the weak
  one ("adds complexity without real protection") is true only for a subset of attackers and hides
  its own scope.
- `SKILL.md` step 4 now directs the agent to fill the threat model first and to reason about every
  dismissal.

### Added
- 4 tests in `tests/test_skill.py` pinning this: the template must contain the threat model block
  *before* Findings, must require the "what would make it apply" column and the "not acceptable for"
  column, and `reporting.md` must explain the assumption/scoping discipline.

## [0.9.13] — beta
### Added
- **`KNOWN_LIMITATIONS.md`** — one page with the honest, *measured* state of the project: retrieval
  below target on paraphrase (0.695 / 0.475 / 0.525 vs 0.70 / 0.60 / 0.60, `templated` 0.916 met),
  fast-gate coverage of 14/30 lab classes (46.7%), **99% of cards' `fix` field is a pointer rather
  than guidance** (2,035 of 2,052), 31 cards leaking raw MASTG front-matter, 254 generic titles,
  1,770 cards with no CWE, plus the honest caveats on scanning and attestation.
- `tests/test_limitations.py` (9 tests) — parses the page's tables and compares them to
  `bench/results.json`, re-counts the corpus defects from `checks/`, and requires the page to be
  linked from README, SECURITY and the threat model. Publishing a better benchmark now forces the
  page to be updated in the same change.

### Changed
- README's stale inline limitation list (which still claimed official-source CWE enrichment was
  unimplemented) replaced with a summary plus a link.
- The threat model's `KNOWN_LIMITATIONS.md` link is restored — it was removed in Phase 1 because the
  file did not exist yet.

## [0.9.12] — beta
### Fixed (determinism — a real bug found by CI)
- **The corpus stamped the build date into every card.** `build_cards_v2.py` and
  `build_authored.py` set `last_verified = datetime.date.today()`, so the same pinned sources
  produced a different `content_hash` on a different day. The determinism job only passed when CI
  happened to run on the day the corpus was built — the "reproducible" claim was false across days.
  `last_verified` now comes from a committed **`CORPUS_DATE`** file, and the build **fails closed**
  if it is missing.
- **A licence detector regression silently weakened provenance.** The 2026-11-01 source refresh
  flipped three OWASP sources (API-Security, Top10, LLM Top 10) to `NOASSERTION`; because
  `confidence` derives from `license`, that would have downgraded 27 cards. Those are CC BY-SA 4.0
  documents, so the registry is corrected and **`refresh_sources.py` now refuses to downgrade a
  known licence to `NOASSERTION`**.
- Net effect: the full rebuild now reproduces the committed `content_hash` exactly
  (`a57da404205eada6`) with **zero card changes** — the fix was in the inputs, not the corpus.

### Added
- `tests/test_determinism.py` (7 tests): `CORPUS_DATE` exists and is shaped; builders never call
  `date.today()`/`datetime.now()`; they fail closed without `CORPUS_DATE`; cards on disk agree with
  it; re-indexing is idempotent.
- **R-017** in the threat model and risk register — the build-date bug, recorded as mitigated with a
  verification that resolves.

## [0.9.11] — beta
### Changed
- **`SECURITY.md` rewritten to the standard content set** — supported-versions table, private
  reporting via GitHub Security Advisories with a "what to include" list, an explicit response-time
  table (48 h acknowledgement, 5 working days assessment, 14/30/90 days for critical/high/medium),
  coordinated-disclosure policy, scope and out-of-scope, and links to the threat model, risk
  register and known limitations.
- Out of scope now says explicitly that a disagreement with an **accepted** risk is itself a valid
  report — the register's IDs give a reviewer something to cite.

### Added
- `tests/test_docs.py` (11 tests) — every relative link and `#anchor` in README, SECURITY,
  CONTRIBUTING, AGENTS and `docs/*.md` must resolve; SECURITY.md must carry the required sections;
  the threat model and register must be linked from README and SECURITY.

## [0.9.10] — beta
### Added
- **`risk-register.yaml`** — the machine-readable twin of `docs/THREAT_MODEL.md` and now the single
  source of truth for risk decisions. 16 entries (`R-001`–`R-016`), each carrying the justification,
  the artefact that verifies it, and the date it must be re-decided.
- **`scripts/check_risks.py`** — enforces the rules that stop the register becoming prose:
  `accepted`/`deferred`/`open` need a justification (≥ 40 chars) *and* a review date; `mitigated`
  needs a verification that **resolves** — a pytest nodeid whose file defines that function, a CI job
  that exists in `ci.yml`, or a doc that exists; a lapsed `review_by` fails the build; and the
  register's ids must match the threat model's matrix exactly.
- `tests/test_risks.py` (12 tests) — one per failure mode, so the validator is itself validated.
- `tests/test_cli.py::test_ensure_db_rebuilds_empty_cache` — a real regression test for R-005: a
  planted empty `kb.sqlite` with a newer mtime must be rebuilt, not trusted.
- CI: a `check_risks.py` step inside `quality-gates`.

### Notes
- Deliberately **not** fixed here: R-007 (dependency lockfile) and R-013 (unbounded read in
  `fingerprint_target`). The register records them; a ledger that also fixes is a ledger that never
  ships.

## [0.9.9] — beta
### Added
- **`docs/THREAT_MODEL.md`** — the project's own STRIDE threat model: scope, components, trust
  boundaries (mermaid), assets ranked by blast radius, 16 risks (`R-001`–`R-016`) each with a
  mitigation *and* a verification, a risk summary matrix, and the security assumptions the design
  rests on. Every risk ID carries forward into `risk-register.yaml` (next phase).
- `tests/test_threat_model.py` — fails when the document drifts: STRIDE tables and the summary
  matrix must contain the same IDs, every status must be one of a fixed set, every relative link
  must resolve, and the code facts it asserts (walk cap, read cap, the unbounded read in
  `fingerprint_target`, the profile-name guard) are re-checked against the source.
- `SECURITY.md` gains a "Threat model" section; the README links it from Security.

### Fixed
- **R-006 corrected during review.** The threat model first claimed `fetch_sources.py` "fails
  closed". It does not: per-file failures are printed but the script exits 0, so a partial fetch is
  not a CI failure by itself — the determinism job is the real backstop. The risk is now rated
  *partially mitigated*.

### Found (open, not fixed)
- **R-013:** `fingerprint_target` reads every file fully into memory with no size cap, so one very
  large file can exhaust RAM. `iter_files` caps at 8,000 files, but this walk is independent and
  unbounded. Tracked in the threat model; a test now fails if it is fixed without updating the doc.

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
