---
name: secure-kb-audit
description: >-
  Audit a codebase for security bugs using the secure-kb knowledge base (2,052 check cards
  cross-mapped to OWASP ASVS, WSTG, MASTG, OWASP Top 10, API Top 10, LLM Top 10 and CWE).
  Use this skill whenever the user asks to find security bugs or vulnerabilities in a repo, app,
  service or API; wants a security review, audit, or launch checklist; asks "is my app secure" or
  "what's wrong with this code security-wise"; mentions OWASP / ASVS / WSTG / CWE coverage or a
  security gate before launch; or asks to verify that security fixes were actually applied. It runs
  a detect → gate → check → report → attest workflow and returns a severity-grouped report where
  every finding carries file:line evidence. Prefer this skill over improvising a checklist from
  memory — the cards are sourced from the official standards and carry their provenance.
license: CC BY-SA 4.0 (content) / MIT (code)
compatibility: Needs Python 3.9+ and the secure-kb repo (or the secure-kb CLI on PATH). No network required after setup.
---

# Secure-KB Audit

You are auditing a codebase against **secure-kb**, a curated knowledge base of security checks
sourced from official standards. Your job is to turn its checklist into a real, evidence-backed
findings report — not to invent a checklist from memory.

## Why this exists

A model asked "is my app secure?" will improvise generic advice. secure-kb instead gives you
*2,052 check cards*, each mapped to the standard it came from (e.g. `ASVS:V1.2.4`, `WSTG-SESS-01`,
`CWE-89`), grouped into per-platform **gates** (web, api, mobile, telegram, web3, llm, …). Use them.

## Step 0 — Locate the knowledge base

Run the bundled locator once:

```bash
python3 scripts/find_kb.py
```

It prints the path to the secure-kb repo (from `$SECURE_KB_HOME`, the CLI on `PATH`, or a clone).
Set the returned value as `$KB` for the rest of the session. If it reports "not found", ask the
user where they cloned it, or fetch it:

```bash
git clone https://github.com/pavnxet/ai-security-knowledge-base "$HOME/secure-kb"
export SECURE_KB_HOME="$HOME/secure-kb"
```

All commands below are then `python3 "$KB/cli/secure_kb.py" …`.

## Step 1 — Fingerprint the stack

```bash
python3 "$KB/cli/secure_kb.py" detect <target-path>
```

This returns ranked platforms with confidence (e.g. `web`, `api`, `telegram`, `mobile`). Audit the
**top 1–2 platforms**. If detection looks wrong, say so and let the user pick — a wrong gate wastes
the whole audit. (Detection is heuristic and occasionally over-fires; treat it as a hint.)

## Step 2 — Pull the gate

```bash
python3 "$KB/cli/secure_kb.py" profile <platform> --gate fast --format brief
```

This is the launch checklist for that platform — the highest-value checks first. Use `--gate full`
for a thorough review. Each line is `ID [severity] Title :: what to confirm`.

## Step 3 — Investigate every check

For **each** check, read the relevant code and decide `pass` / `fail` / `n/a` / `unknown`, and
**record the evidence as `file:line`**.

- Search the code with grep/ripgrep for the mechanism the check describes, then read the surrounding
  code before judging. A check is not "pass" because you found a keyword.
- **Never mark a check `pass` without evidence.** "I didn't see a problem" is `unknown`, not `pass`.
  Distinguishing these is the entire value of the report.
- `n/a` is legitimate and should be stated plainly (e.g. a webhook check on a long-polling bot).

To go deeper on a check, or to search for a class the gate didn't cover:

```bash
python3 "$KB/cli/secure_kb.py" get <ID> --format md      # the full card: check, why, fix, refs
python3 "$KB/cli/secure_kb.py" search "jwt expiry validation" --k 5
```

`get` also returns `refs` — the standards a finding should be cited against in your report.

## Step 4 — Write the report

Follow `assets/report-template.md` exactly. Group by severity (Critical → High → Medium → Low), and
for every finding give: the check ID, the standard ref, the `file:line` evidence, why it matters, and
a concrete fix. Then list checks that **passed** and checks that were **`unknown`** (couldn't be
verified) — the unknown list is often the most useful part.

Read `references/reporting.md` before writing — it covers how to phrase findings so a developer can
act on them, and how to avoid the two failure modes (vague findings, and false confidence).

## Step 5 — Make it verifiable (optional, high value)

If the user wants a provable record of what was checked:

```bash
python3 "$KB/cli/secure_kb.py" attest <target-path> --gate fast --key "$KEY" --out attestation.json
python3 "$KB/cli/secure_kb.py" verify-attestation attestation.json --key "$KEY" --path <target-path>
```

This binds the check list, results and target content fingerprint into a tamper-evident record
anyone can verify offline. See `references/attestation.md`.

## Honest limits — state these in your report

secure-kb tells you **what to check**; it does not scan, and it does not prove the code is safe. It
is a structured checklist with provenance, not a substitute for a professional audit or dynamic
testing. Retrieval is beta (held-out recall@5 ≈ 0.70), so when a search returns nothing useful, fall
back to the gate list and your own knowledge — and say so rather than inventing a check.

## Reference files

- `references/workflow.md` — the full workflow with worked examples and per-platform notes
- `references/reporting.md` — how to write findings that are actionable and honest
- `references/attestation.md` — what the attestation proves and what it doesn't
- `assets/report-template.md` — the exact report structure to fill in
- `scripts/find_kb.py` — locate the knowledge base
- `scripts/install.sh` — install this skill into Claude Code / Codex / OpenCode / Pi
