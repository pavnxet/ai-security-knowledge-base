# Known limitations

Everything here is measured, not estimated. The numbers are checked against `bench/results.json` by
`tests/test_limitations.py`, so this page cannot quietly drift from reality.

If you are deciding whether to trust `secure-kb` for something, read this first. It is deliberately
blunt: a knowledge base that overstates itself is worse than one with a shorter feature list.

---

## 1. Retrieval is below target

The KB finds the right card for a **clearly worded** question. It is weak on paraphrase — the same
question in a developer's own words.

| Set | n | recall@5 | Target | Status |
|---|---|---|---|---|
| Held-out (all) | 154 | 0.695 | 0.70 | below |
| Curated v1 | 59 | 0.339 | — | — |
| Curated v2 | 59 | 0.475 | 0.60 | below |
| v2_dev (developer vocabulary) | 40 | 0.525 | 0.60 | below |
| Templated | 95 | 0.916 | 0.90 | met |

**Why:** retrieval is **lexical** (SQLite FTS5 + BM25), not semantic. It is strong when your words
overlap the card's (`templated` 0.916) and weak when they do not. There are no embeddings. Query
normalisation and official-CWE expansion lifted this from 0.669/0.475/0.425, but they do not close
the paraphrase gap.

**What to do about it:** use `get_profile` (the gate list) as the primary checklist rather than
relying on `search_checks` alone. The gate does not depend on your wording.

## 2. The fast gate covers less than half the lab classes

| Metric | Value | Target |
|---|---|---|
| Lab vulnerability classes known | 30 | — |
| Present anywhere in the corpus | 23 (76.7%) | — |
| Present in the `fast` gate | 14 (**46.7%**) | 70% |

A `fast` gate review will miss classes that exist in the corpus but are not in the gate. Use
`--gate full` for coverage, and treat the gate as a starting point rather than a complete audit.

## 3. Most cards do not contain remediation guidance

| Defect | Cards | Share |
|---|---|---|
| `fix` field is a **pointer** ("See OWASP/mastg … for remediation"), not guidance | 2,035 | **99%** |
| Cards with actual written remediation | 17 | 1% |
| Cards with raw MASTG YAML front-matter leaking into `check` | 31 | 1.5% |
| Cards with a generic title ("References", "Introduction", …) | 254 | 12% |
| Cards carrying no CWE | 1,770 | 86% |

This is the biggest content limitation. A card reliably tells you **what to check** and **why it
matters**; it usually does **not** tell you how to fix it — it points at the upstream document.
Do not present a card's `fix` as advice without following the pointer.

## 4. It does not scan anything

`secure-kb` is a checklist with provenance. It reads your code only to fingerprint the stack
(`detect`) or to bind an attestation to a content hash. It does not find vulnerabilities, does not
run SAST/DAST, and cannot tell you whether your code is safe. Every finding in a report comes from
the agent reading your code against these cards.

## 5. An attestation proves what was claimed, not that it is true

`attest` binds the check list, results and evidence hashes to the KB build and the target's content
fingerprint. It makes a claim **falsifiable and attributable**. It does not verify that the checks
were performed correctly or honestly, and there is no external timestamp authority — an issuer can
state any time they like (risk `R-008`).

## 6. Detection is heuristic

`detect` infers the platform from file names and content signatures. It over-fires: a repo with a
`prompts/` folder and no LLM API call still scores `llm` highly. Treat its output as a hint and
confirm the platform yourself before auditing the wrong gate.

## 7. The skill needs the knowledge base installed

`skills/secure-kb-audit` is instructions, not the data. It locates the KB via `SECURE_KB_HOME`, a
`secure-kb` on `PATH`, or a common clone path. Without one, it can only tell you to install it.

## 8. First call is slow on a cold checkout

The index is built on first use (`ensure_db`) from `index/checks.jsonl`. That takes a few seconds on
a cold checkout; later calls are sub-second. `kb.sqlite` is generated, never committed.

---

## What is *not* a limitation

Worth stating, because these are often assumed to be broken:

- **The corpus build is reproducible.** The same pinned sources produce the same `content_hash` on
  any day (`CORPUS_DATE`), verified in CI.
- **Every accepted risk has a reason.** `risk-register.yaml` is enforced by `scripts/check_risks.py`.
- **Provenance is real.** Each card records the source repo, path, anchor and pinned commit.
- **Ingested text is treated as data.** It is never executed, and instructions inside it are never
  followed.
