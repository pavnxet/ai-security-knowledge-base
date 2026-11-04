# Security Audit — <target> (<platform(s)>)

**Scope:** <what was audited, at which commit/path>
**Gate:** `<platform>` / `<fast|full>` — <N> checks
**Knowledge base:** secure-kb `<version>` (`content_hash` `<hash>`)
**Method:** static review against secure-kb cards. Not a dynamic test or professional audit.

## Threat model

Fill this in **before** writing findings. Without it, a dismissal is just an opinion.

| | |
|---|---|
| **Assets** | <what this app actually protects: credentials, payment data, admin actions, the user's own account/session> |
| **Trust boundaries** | <where untrusted input crosses into trusted code — the points worth checking hardest> |
| **Assumptions** | <what you are taking for granted: single-user, local-only, TLS terminated upstream, no multi-tenant use, …> |
| **Out of scope** | <what you are not assessing, and why> |

## Summary

| Severity | Found | Verified pass | Unknown | N/A |
|---|---|---|---|---|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |

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
| `<ID>` | `<file>:<line>` | <what you actually saw — not "no problem found"> |

## Could not verify (unknown)

| Check | Why it couldn't be verified | What the user should check |
|---|---|---|
| `<ID>` | <e.g. needs a running instance / config not in repo> | <the question to answer> |

## Not applicable

Every row needs a reason **and** the condition that would make it apply.

| Check | Why it does not apply | What would make it apply |
|---|---|---|
| `<ID>` | <argue from the code's own constraints> | <e.g. "if this ever adds a webhook endpoint"> |

## Accepted risks

A risk you are choosing not to fix must say who it is acceptable *for*. That sentence is what makes
the decision reviewable — and it is where hand-waving shows.

| Check | Why it is accepted | Acceptable for | **Not** acceptable for |
|---|---|---|---|
| `<ID>` | <the reason, argued from the code's constraints> | <e.g. single-user local tool> | <e.g. any multi-tenant deployment> |

## Coverage caveats

- Retrieval is beta (held-out recall@5 ≈ 0.70); a `search` that returns nothing does not prove a
  class is absent — the gate list is the authoritative checklist.
- Detection is heuristic; platform mis-detection is possible.
- This is a static review. Anything requiring a running system (auth flows, rate limits, headers at
  runtime) is marked `unknown`, not `pass`.
