# Verifiable Security Attestation (VSA)

**A deterministic, tamper-evident proof of what an AI agent verified, against which knowledge-base
version, bound to the exact content of the code it inspected — verifiable offline by anyone.**

This is the core new capability in this release. It exists to solve a specific, growing problem:
when an AI coding agent says *"I checked this app for security issues and it's fine"*, nobody can
independently check that claim. VSA makes the claim **falsifiable**.

## The problem

Agent-written security summaries are unfalsifiable:
- You cannot tell **which checks** were actually run.
- You cannot tell **what version** of the knowledge base was used (so you can't tell if the checks
  were current).
- You cannot tell whether the code **changed** after the claim was made.
- The claim is **unsigned prose** — trivial to edit after the fact.

## What VSA produces

One small JSON file:

```json
{
  "attestation_version": 1,
  "attestation_id": "90cfed6e91ab…3942b",
  "kb":     {"name": "secure-kb", "version": "0.9.0", "content_hash": "0c921baa291a4af4"},
  "target": {"path": "/app", "fingerprint": "1f9c…", "file_count": 128},
  "gate":   {"profile": "web", "name": "fast", "check_count": 25},
  "checks": [{"id": "SKB-ASVS-V1-2-4", "status": "unknown", "evidence_sha256": null}, …],
  "signature": {"alg": "HMAC-SHA256", "value": "…"}
}
```

Three things are bound together by cryptography:

1. **What was checked** — the exact list of check ids and their results, each result's evidence
   hashed (`evidence_sha256`) so the evidence can't be swapped.
2. **Against which knowledge base** — `kb.content_hash` is the deterministic build hash of the
   corpus. Two attestations are only comparable if this matches.
3. **Against which code** — `target.fingerprint` is a SHA-256 over the sorted
   `(relative-path, file-sha256)` pairs of the inspected tree. Change one byte anywhere and the
   fingerprint changes.

`attestation_id` = `SHA-256(canonical_json(payload))`. The signature (optional) is an HMAC over that
id. Nothing else is needed to verify.

## Use

```bash
# Produce an attestation (optionally signed, optionally with real results)
secure-kb attest ./my-app --gate fast --key "$AGENT_KEY" --out attestation.json
secure-kb attest ./my-app --gate fast --results results.json --out attestation.json

# Verify offline — no network, no trust in the agent
secure-kb verify-attestation attestation.json --key "$AGENT_KEY" --path ./my-app
# -> {"status":"VALID","kb_match":true,"checks":25,"problems":[]}   exit 0
```

`--path` re-computes the target fingerprint, so verification also catches *"the code changed after
the attestation"*. Exit code is `0` for VALID and `1` for INVALID.

Over MCP the same two operations are exposed as the tools **`attest`** and **`verify_attestation`**,
so an agent can produce and self-verify an attestation without shelling out.

## What verification proves — and what it does not

**Proves:**
- The check list, results and evidence hashes are exactly as issued (any edit breaks `attestation_id`).
- The claim was made against this exact KB build and this exact code fingerprint.
- If signed, the issuer held the key.

**Does not prove:**
- That the checks were performed *correctly* or honestly — it proves **what was claimed**, not that
  the claim is true. It makes a false claim **detectable and attributable**, which is the point.
- That the gate was sufficient — use `--gate full` for coverage, and read the KB's own limitations.

## Why this is useful for AI agents specifically

- **Accountability without trust.** A reviewer verifies an agent's security claim in one command,
  offline, without running the agent again.
- **CI gate.** Fail a build if `verify-attestation` reports INVALID, or if the attested `kb` hash is
  not the current one — i.e. block merges made against a stale knowledge base.
- **Reproducible audits.** Two agents, same code + same KB hash → the same attestation id, so their
  work is directly comparable.
- **Supply-chain friendly.** The attestation is a plain, diffable file that can be attached to a
  release, a PR, or an SBOM.

## Design notes

- **Deterministic.** Canonical JSON (sorted keys, no whitespace) means the id depends only on the
  bound content, not on formatting or timestamp.
- **No timestamps in the id.** The payload deliberately excludes wall-clock time so the id is
  reproducible; the file may carry a timestamp outside the signed payload.
- **Stdlib only.** `hashlib` + `hmac` + `json` — no new dependencies, no network.
- **Small.** An attestation for a 25-check gate is a few KB.
