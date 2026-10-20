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

## Tone

Write for the developer who has to act on it, and for the reviewer who has to trust it. Direct,
specific, no filler. State the good news too — a verified-pass table tells the reader their existing
hardening is real, which is information, not padding.
