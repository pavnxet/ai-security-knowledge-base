# Audit output contract

Every audit produces **`findings.json`**, validated against
[`audit/report-schema.json`](../audit/report-schema.json) by
[`scripts/validate_findings.py`](../scripts/validate_findings.py).

The point of a schema rather than a prose report: prose cannot be deduplicated, re-verified, or
compared between runs. Three specific mistakes are easy to make in prose and impossible to make here.

```bash
python3 scripts/validate_findings.py audit/findings.json
# -> findings OK — 3 record(s): confirmed=1, needs_validation=1, rejected=1
```

Exit code is `0` when valid, `1` otherwise, so it drops into CI.

---

## The three verdicts

| Verdict | Means | Carries severity? |
|---|---|---|
| `confirmed` | A source-grounded issue that was demonstrated, with a complete trace from where input enters to where it takes effect | **Yes** |
| `needs_validation` | A candidate with one exact unresolved fact | **No** |
| `rejected` | A candidate that was disproved, with the reason | **No** |

### Why `needs_validation` carries no severity

Rating an unproven issue is the most common way a security report loses credibility: it claims impact
it cannot demonstrate, and the reader has no way to tell which claims are grounded. An unvalidated
candidate has **no known impact**, so it has no severity. It has a `validation_plan` instead.

The validator enforces this: putting `severity` on a `needs_validation` or `rejected` record is a
build failure.

### Why `confirmed` needs a trace

A `confirmed` record must carry a `trace` array with at least one step of each kind:

| `kind` | What it is |
|---|---|
| `entrypoint` | where attacker-controlled input enters |
| `propagation` | how it travels (optional, repeatable) |
| `sink` | where it takes effect |

The validator rejects a `confirmed` record with no `sink` — because a claim that never reaches a sink
is a hypothesis, not a finding. This is the rule that stops "I found a suspicious string" from being
reported as a vulnerability.

---

## Record shapes

### `confirmed`

```json
{
  "verdict": "confirmed",
  "fingerprint": "authz/admin-route-missing-guard",
  "title": "Admin route reachable without the owner check",
  "description": "...",
  "root_cause": "...",
  "intended_behavior": "...",
  "trace": [
    { "kind": "entrypoint",  "file": "internal/app/server.go", "line": 205, "scope": "ServeHTTP",   "description": "request enters the router" },
    { "kind": "propagation", "file": "internal/app/server.go", "line": 215, "scope": "route switch", "description": "dispatch without a guard" },
    { "kind": "sink",        "file": "internal/app/admin.go",  "line": 42,  "scope": "adminHandler", "description": "privileged action executes" }
  ],
  "evidence": "...", "conditions": "...", "execution": "...", "remediation": "...",
  "severity": "high",
  "confidence": "high",
  "card_id": "SKB-TG-ACCESS-0037",
  "kb": { "version": "0.9.17", "content_hash": "a57da404205eada6" }
}
```

### `needs_validation`

```json
{
  "verdict": "needs_validation",
  "fingerprint": "ratelimit/absent-on-login",
  "title": "Login endpoint may have no rate limit",
  "description": "...",
  "claimed_root_cause": "...",
  "trace": [ { "kind": "entrypoint", "file": "internal/app/server.go", "line": 300, "scope": "login", "description": "POST /login" } ],
  "evidence": "...",
  "blockers": ["proxy configuration is not in the repository"],
  "validation_plan": "Inspect the ingress config, or run a bounded local loop against a fixture.",
  "card_id": "SKB-API-API4-2023"
}
```

No `severity` field. `blockers` must be non-empty — "I could not verify it" is only useful if it says
*what would be needed*.

### `rejected`

```json
{
  "verdict": "rejected",
  "fingerprint": "injection/sql-in-query-builder",
  "title": "Possible SQL injection in the query builder",
  "description": "...",
  "claimed_root_cause": "...",
  "trace": [ { "kind": "entrypoint", "file": "internal/store/query.go", "line": 88, "scope": "Build", "description": "query built from a map" } ],
  "evidence": "...",
  "reason": "Disproved: the interpolated part is a constant chosen from an allowlist, not attacker input."
}
```

`reason` is mandatory. A dismissal without one is indistinguishable from an oversight — the same rule
the skill applies to `n/a` rows in the prose report.

---

## The two fields that bind a record to the corpus

| Field | Purpose |
|---|---|
| `card_id` | which secure-kb card motivated this check (e.g. `SKB-TG-ACCESS-0037`) |
| `kb` | `{version, content_hash}` of the corpus that produced the record |

Without `kb`, two audits are not comparable: "we found 3 issues" means nothing if one ran against a
different corpus. With it, a run is reproducible and an attestation can bind the result to a specific
knowledge-base build.

## Fingerprints

`fingerprint` is a stable, source-derived identifier (`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`). It must
**not** change when a record moves between verdicts — that is how the same candidate is tracked from
`needs_validation` to `confirmed` or `rejected` across runs. The validator rejects duplicates.

---

## What the validator checks

| Rule | Why |
|---|---|
| Required fields per verdict | a `confirmed` record missing `remediation` is not actionable |
| `severity` absent on `needs_validation` / `rejected` | unproven issues have no impact to rate |
| `confirmed` trace contains an `entrypoint` **and** a `sink` | a claim that never reaches a sink is a hypothesis |
| `trace[].line` is a positive integer | a trace step you cannot point at is not a trace step |
| `fingerprint` unique across records | otherwise the same issue is counted twice |
| `fingerprint`, `card_id`, `kb.content_hash` patterns | stable ids and a real 16-hex corpus hash |
| `blockers` non-empty on `needs_validation` | "couldn't verify" must say what is missing |

## Worked example

[`audit/findings.example.json`](../audit/findings.example.json) contains one valid record of each
verdict. `tests/test_findings_schema.py` mutates it once per rule to prove the validator fails — 14
tests, so the validator cannot quietly become a check that always passes.

## Related

- [`skills/secure-kb-audit/SKILL.md`](../skills/secure-kb-audit/SKILL.md) — the audit workflow that produces these records
- [`docs/ATTESTATION.md`](ATTESTATION.md) — binding a run to the corpus and verifying it offline
- [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) — what the KB behind these records cannot do
