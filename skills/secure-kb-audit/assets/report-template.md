# Security Audit — <target> (<platform(s)>)

**Scope:** <what was audited, at which commit/path>
**Gate:** `<platform>` / `<fast|full>` — <N> checks
**Knowledge base:** secure-kb `<version>` (`content_hash` `<hash>`)
**Method:** static review against secure-kb cards. Not a dynamic test or professional audit.

## Summary

| Severity | Found | Verified pass | Unknown |
|---|---|---|---|
| Critical | | | |
| High | | | |
| Medium | | | |
| Low | | | |

One-paragraph plain-language verdict: what the biggest risk is, and what to do first.

## Findings

### [CRITICAL] <short title> — `<CHECK-ID>`
**Standard:** `<ref, e.g. ASVS:V6.2.9 / CWE-798>`
**Evidence:** `<file>:<line>` — <the exact line(s), quoted briefly>
**Why it matters:** <concrete impact for *this* app, not generic boilerplate>
**Fix:** <the specific change, ideally with a code sketch>

### [HIGH] <short title> — `<CHECK-ID>`
…same shape…

## Verified passing

| Check | Evidence | What was confirmed |
|---|---|---|
| `<ID>` | `<file>:<line>` | <what you actually saw> |

## Could not verify (unknown)

| Check | Why it couldn't be verified | What the user should check |
|---|---|---|
| `<ID>` | <e.g. needs a running instance / config not in repo> | <the question to answer> |

## Not applicable

- `<ID>` — <why, e.g. "no webhook; this bot uses long polling">

## Coverage caveats

- Retrieval is beta (held-out recall@5 ≈ 0.70); a `search` that returns nothing does not prove a
  class is absent — the gate list is the authoritative checklist.
- Detection is heuristic; platform mis-detection is possible.
- This is a static review. Anything requiring a running system (auth flows, rate limits, headers at
  runtime) is marked `unknown`, not `pass`.
