# Writing findings that are actionable and honest

An audit report has one job: let a developer fix the real problems and trust the rest. Two failure
modes destroy that, and both are easy to fall into.

## Failure mode 1 — vague findings

"The app has weak authentication" is useless. A finding must be falsifiable: a reader should be able
to open the file and see whether you are right. That means:

- **`file:line` evidence on every finding.** If you cannot point at a line, it is not a finding — it
  is a question, and it belongs in "could not verify".
- **Quote the line.** One or two lines of the actual code, so the reader doesn't have to hunt.
- **Say the impact for *this* app.** "Session file is world-readable" matters more on a shared host;
  a Telegram userbot's session grants full account access, so it matters everywhere. Tie severity to
  what this specific program is and does.
- **Give the fix.** A finding without a fix is a complaint. Prefer the smallest change that closes it.

## Failure mode 2 — false confidence

The dangerous error is marking something `pass` because you didn't find a problem. "I grepped and saw
nothing" is not evidence of absence. Rules:

- `pass` requires positive evidence — you saw the control *in the code*.
- If you couldn't determine it, say `unknown`. An honest "unknown" list is more valuable than a
  padded "pass" list, because it tells the reader exactly where to look next.
- Never let the report's tone exceed its evidence. If you reviewed statically, say so; do not imply
  runtime testing.

## Dismissing a finding

The most dangerous sentence in a security report is "not applicable". A dismissal that nobody can
argue with is indistinguishable from an oversight, so a good one has three parts:

1. **Argue from the code's own constraints**, not from preference. "This can't happen because the
   only writer refuses that input" beats "we don't consider that a risk".
2. **State the assumption the argument rests on.** Every invariant argument has one. Name it, so a
   reviewer can attack it.
3. **Name who it is acceptable for, and who it is not.** "Fine for a single-user local tool, not fine
   for a multi-tenant service" is a decision. "Not a problem" is not.

Then add the condition that would flip it: *"this becomes a finding if the app ever adds a webhook."*

### Worked example — the same rejection, strong and weak

A review flagged that a secrets-redaction minimum was set to 8 characters instead of 16.

**Strong.** *"Rejected: `Settings` refuses to save a header or env value shorter than 8 characters,
and redaction cuts every saved value of 8+ characters out of server responses. The save floor and the
redaction floor are the same number, so raising the minimum to 16 would reject 8–15 character secrets
without making redaction any stronger. Assumption: `Settings` is the only path by which a saved value
enters — if a value can also arrive from the OS environment, shorter values can exist and this
becomes a real finding. Acceptable for a single-user desktop app; not acceptable for a hosted
service."*

That is arguable. A reviewer can attack the assumption and knows exactly what would change the answer.

**Weak.** *"Rejected: same-machine encryption adds complexity without real protection."*

It sounds decisive and is close to true — against an attacker who already runs as the user. It is
**false** against other local accounts, backups, cloud-synced folders, and malware that reads files
but does not run as the user. The sentence hides its own scope, which is exactly the failure mode to
avoid: the claim is only true for a subset of attackers, and the report does not say which.

### The test for your own dismissal

Before writing "not applicable", ask: *could a competent reviewer disagree with this from the
information in my report alone?* If yes, the reason is incomplete — add the invariant, the
assumption, or the scope.

## Severity — assign it, don't inherit it

The card's severity is a **default for that check class**, not a verdict on this codebase. Adjust:

- Raise it when the asset is high-value (credentials, payment, admin actions, a userbot session that
  controls a whole account).
- Lower it when the check is structurally impossible here (a webhook check on a long-polling bot is
  `n/a`, not a finding).
- If you disagree with the card's severity, say why in one clause. That is useful signal.

## Calibrating the "could not verify" list

Aim for precision about *why* something is unknown:

- *Needs a running system* — rate limits, security headers, TLS config.
- *Needs context outside the repo* — deployment config, secrets management, WAF rules.
- *Ambiguous in the code* — the control exists but its correctness depends on an input you can't trace.

Each of those implies a different next action for the user, so name the category.

## The machine-checked form

The prose report is for humans; `findings.json` is the contract (see `docs/AUDIT-OUTPUT.md`). The two
must agree — deriving the prose from the validated JSON is the only way to guarantee that. Three rules
the validator enforces, and they map directly onto the advice above:

- `confirmed` must trace `entrypoint` → `sink` — the same "point at where it takes effect" rule.
- `needs_validation` may not carry a severity — an unproven issue has no impact to rate.
- `rejected` must carry a reason — a dismissal nobody can argue with is indistinguishable from an
  oversight.

## Tone

Write for the developer who has to act on it, and for the reviewer who has to trust it. Direct,
specific, no filler. State the good news too — a verified-pass table tells the reader their existing
hardening is real, which is information, not padding.
