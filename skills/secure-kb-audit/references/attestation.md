# Verifiable Security Attestation

## The problem it solves

An agent's security summary is normally unfalsifiable prose. A reviewer cannot tell which checks ran,
against which version of the knowledge base, or whether the code changed afterwards. The attestation
makes the claim **falsifiable**.

## Use

```bash
SK="python3 $SECURE_KB_HOME/cli/secure_kb.py"

$SK attest ./target --gate fast --key "$KEY" --out attestation.json
$SK verify-attestation attestation.json --key "$KEY" --path ./target
# -> {"status":"VALID","kb_match":true,"checks":25,"problems":[]}   exit 0
```

Exit code is `0` for VALID and `1` for INVALID, so it drops straight into CI.

## What it binds

- **What was checked** — the check ids, their results, and a SHA-256 of each result's evidence, so
  evidence cannot be swapped after the fact.
- **Against which knowledge base** — the corpus's deterministic `content_hash`. Two attestations are
  only comparable if this matches, so it also catches "audited against a stale KB".
- **Against which code** — a SHA-256 over the target's sorted `(path, file-hash)` pairs. Change one
  byte anywhere and `--path` verification fails.

The id is `SHA-256(canonical_json(payload))`, optionally HMAC-signed. Any edit breaks it.

## What it proves — and what it does not

**Proves:** the check list, results and evidence hashes are exactly as issued; the claim was made
against this KB build and this exact code; if signed, the issuer held the key.

**Does not prove:** that the checks were performed *correctly or honestly*. It proves **what was
claimed**, not that the claim is true. It makes a false or careless claim *detectable and
attributable*, which is the point. Say this plainly in the report — an attestation is a record of
diligence, not a certificate of safety.

## Over MCP

If the user's agent runs against the MCP server (`mcp/server.py`), the same operations are the tools
`attest` and `verify_attestation` — no shell needed.
