# Security Policy

## What this repository is

secure-kb is a **knowledge base of security checks** — it contains no running service and executes
nothing against any target. The "vulnerabilities" it discusses are defensive checks, not exploits.

## Scope — what counts as a security issue *here*

- A **leaked credential** accidentally committed to this repo (scripts, staging, bench, index).
- A card that contains **working exploit code, payload lists, or weaponised content** (this should
  never happen — cards are defensive by policy).
- A **prompt-injection / instruction-injection** payload in ingested source text that was not
  neutralised (all ingested text is treated as data; see `AGENTS.md`).
- A **dependency or tooling** issue in the CLI/MCP that could be abused (e.g. path traversal when
  reading a target).

Out of scope: the accuracy of a third-party source, and vulnerabilities in the tools we *describe*
in `tools/*.yaml` (report those to the tool's own project).

## How to report

1. **Do not** open a public issue for a leaked credential. Use GitHub's private
   "Report a vulnerability" (Security tab → Advisories) on this repository.
2. Include: what you found, the file path, and (for a leaked secret) whether it is still live.
3. We will acknowledge within **5 working days** and aim to remediate a live secret within **48 hours**
   (rotate first, then purge from history).

## What we do on our side

- Secret scanning (gitleaks + trufflehog) runs in CI and over git history — see
  `PRE_PUBLIC_CHECKLIST.md`.
- Ingested text is treated strictly as **untrusted data**: it is never executed, and the CLI/MCP
  never follow instructions found inside card text. Normalisation strips markdown/control noise,
  but it does **not** remove instruction-like phrases (some cards intentionally quote examples of
  prompt-injection attacks). `AGENTS.md` states this policy.
- The CLI and MCP server are **read-only** on any target codebase by default.

## Supported versions

Only the latest tagged release is supported. Pre-releases are explicitly marked as such.
