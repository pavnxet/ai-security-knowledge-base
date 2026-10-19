# PRE_PUBLIC_CHECKLIST.md

Evidence-based readiness review for making `secure-kb` public. **Visibility is NOT changed by this
document.** Each item lists the command run and its result.

---

## 1. `staging/` — no NONE-license or reference-only text

`staging/` holds the raw parsed items that cards are built from. Per-source licence audit
(`sources.yaml` is the source of truth):

| staging file | source repo | licence | items |
|---|---|---|---|
| OWASP__ASVS.jsonl | OWASP/ASVS | CC-BY-SA-4.0 | 345 |
| OWASP__CheatSheetSeries.jsonl | OWASP/CheatSheetSeries | CC-BY-SA-4.0 | 169 |
| OWASP__wstg.jsonl | OWASP/wstg | CC-BY-SA-4.0 | 115 |
| OWASP__mastg.jsonl | OWASP/mastg | CC-BY-SA-4.0 | 78 |
| OWASP__masvs.jsonl | OWASP/masvs | CC-BY-SA-4.0 | 24 |
| OWASP__owasp-istg.jsonl | OWASP/owasp-istg | CC-BY-SA-4.0 | 19 |
| OWASP__Top10.jsonl | OWASP/Top10 | CC-BY-SA-4.0 | 9 |
| OWASP__API-Security.jsonl | OWASP/API-Security | CC-BY-SA-4.0 (project-declared) | 9 |
| OWASP__www-project-…LLM….jsonl | OWASP/…LLM Top 10 | CC-BY-SA-4.0 (project-declared) | 9 |
| kadenzipfel__smart-contract-vulnerabilities.jsonl | kadenzipfel/… | MIT | 38 |
| raroque__vibe-security-skill.jsonl | raroque/… | MIT | 39 |
| crytic__not-so-smart-contracts.jsonl | crytic/… | Apache-2.0 | 11 |

- **NONE-license staged sources: 0.** The only NONE-license source
  (`ConsenSysDiligence/smart-contract-best-practices`) was removed from staging and its 6 derived
  cards deleted in v0.2.0.
- **Action taken:** `staging/` is now **removed from git** (added to `.gitignore`); only the
  regenerating scripts (`scripts/ingest/`) are shipped. `git ls-files | grep -c '^staging/'` → **0**.

## 2. `legacy/` (from-memory v0.1 cards)

- `legacy/v0.1_checks/` (76 hand-written cards, all `from-memory`) is **removed from git**
  (`.gitignore`). `git ls-files | grep -c '^legacy/'` → **0**.
- They are **excluded from the index, search and gates** — `index/checks.jsonl` contains only v0.2
  cards. Their IDs remain resolvable via `index/aliases.json` (13 map to a v0.2 card).
- The audit record is retained in `AUDIT_v0.1.md`.

## 3. Secret scan (working tree + full git history)

Tools: **gitleaks 8.30.1** and **trufflehog 3.99.2** (release binaries; run with `ulimit -v unlimited`).

| scan | command | findings |
|---|---|---|
| gitleaks, git history | `gitleaks git --report-format json …` | 40 → **0** after allowlist |
| gitleaks, working tree | `gitleaks dir --report-format json …` | 40 → **0** after allowlist |
| trufflehog, filesystem | `trufflehog filesystem . --no-verification --json` | 2 |
| trufflehog, git history | `trufflehog git file://. --no-verification --json` | 1 |

**All findings are false positives**, verified individually:
- gitleaks `generic-api-key`: matched **card IDs** such as `SKB-W-SECRETS-2379` (high-entropy id
  strings) and detection-regex literals in `scripts/build_tools.py`. Suppressed by `.gitleaks.toml`
  (allowlist on `SKB-[A-Z0-9-]+`); re-run → **0 findings**.
- trufflehog `Postgres`: matched the documentation placeholder
  a Postgres connection-string placeholder (user:password@host) in a vibe-security reference file and a git blob.
  Not a credential. Excluded via `.trufflehog-exclude.txt`.

**Real secrets found: 0.** No GitHub token, no credential appears in scripts, logs, staging, bench,
or history. (The scanners themselves never received a token.)

## 4. GitHub Actions on the PR

| run (head) | workflow | result |
|---|---|---|
| 8251bfb3 | ci | ❌ failure — stale workflow referenced `build_cards.py`/`build_profiles.py` (removed in v0.2) |
| 9b6e6deb | ci | ❌ failure — same stale workflow |
| 9791b18a | ci | quality-gates ✅ · secret-scan ❌ (trufflehog FP) |
| c0dedf6c (final) | ci | **quality-gates ✅ · secret-scan ✅ — CI GREEN** |

**Fix applied:** `ci.yml` rewritten for the v0.2 pipeline (`tests/validate.py` + `bench/run_bench.py`
+ CLI smoke + zero-dep check) and a `secret-scan` job added (gitleaks binary + trufflehog).
Both jobs **pass on CI (run c0dedf6c)**.
**Trade-off:** the trufflehog step is **report-only** — it prints findings but does not gate, because
its `GitHubOauth2` detector cannot distinguish our provenance commit SHAs from tokens. **gitleaks
(context-aware) is the gating scanner** and passes with the allowlist.

Environment differences found and fixed: the workflow ran on a clean runner where (a) the old build
scripts no longer exist and (b) `staging/` is absent (gitignored), so the CI no longer tries to
rebuild cards from sources it doesn't have — it validates the committed artifacts instead.

## 5. Licence consistency

| file | says | consistent? |
|---|---|---|
| `LICENSE` | MIT for **code** | ✅ |
| `LICENSES/CONTENT.md` | CC BY-SA 4.0 for **content** + project-declared table | ✅ |
| `NOTICE.md` | generated from `sources.yaml`; lists all 67 sources + licence | ✅ |
| `sources.yaml` | 67 sources; `license` read from repo where fetchable | ✅ |

Sources whose licence is **project-declared (not machine-read)**: `OWASP/API-Security`,
`OWASP/…LLM Top 10`. Sources with **NONE** licence: `ConsenSysDiligence/smart-contract-best-practices`
(reference-only, no text derived).

## 6. Repo hygiene files

- `SECURITY.md` — how to report issues in the KB itself. ✅ added.
- `CONTRIBUTING.md` — how to add a card/source; gates to run. ✅ added.
- Repo description + topics — see §7.

## 7. Repo description & topics

Set via the GitHub API on the PR branch merge (see BUILD_REPORT). Intended:
description = "Merged, AI-agent-searchable security verification knowledge base…";
topics = `security, appsec, owasp, secure-coding, ai-agent, mcp, checklist, vulnerability`.

## 8. Fresh-install test from the remote

Method: downloaded the **branch archive from GitHub** (`GITHUB_DOWNLOAD_A_REPOSITORY_ARCHIVE_ZIP`,
ref `v0.2.1`) into a clean directory — a genuine remote checkout, not the working copy.

```
fresh checkout: 955 files, 6.8 MB
detect /scratch/.../sample   -> platforms: telegram(4), web(3), llm(2), api(2)     0.29 s
profile web --gate fast      -> 25 checks                                          0.36 s
search "sqli parameterized"  -> SKB-W-INJECTION-5201 (V1.2.4 parameterized queries) 0.23 s
MCP initialize + search_checks (supabase rls) -> 2 cards                           ok
zero-dep: jq on index/checks.jsonl ; cut on index/brief.tsv                        ok
```

All five interfaces work from a cold remote checkout with **no install and no build step**.
(A `detect` regression found during this test — empty `router.json` — was fixed in `phase_d.py` and
re-verified.) Private-repo clone instructions are in the README; the public form is already written.

---

## Open items / not done

- Tool adapters: **4/12 verified** against their READMEs (gitleaks, trufflehog, semgrep,
  dependency-check). The other 8 are marked `verified: false`.
- Telegram `secret_token` claim: unverified from the fetched doc excerpt.
- Benchmark curated expectations: v1 refs were memory-written (27/59 invalid); v2 refs are derived
  from standards text but the matcher is crude — both are reported.
