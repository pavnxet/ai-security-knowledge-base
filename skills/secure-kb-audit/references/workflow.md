# The audit workflow, with a worked example

## The five commands

```bash
KB="$SECURE_KB_HOME"                       # or the output of scripts/find_kb.py
SK="python3 $KB/cli/secure_kb.py"

$SK detect  ./target                       # 1. what is this?
$SK profile telegram --gate fast           # 2. the checklist for that platform
$SK search  "telegram session string" -k 5 # 3. go deeper on a class
$SK get     SKB-TG-SECRETS-0033 --format md# 4. the full card for one check
$SK attest  ./target --gate fast --out a.json   # 5. verifiable record (optional)
```

## Worked example — a Telegram userbot

**Detect** returned `llm` (90) and `telegram` (48). The `llm` hit was a **false positive** (the repo
had a `prompts/` folder but made no LLM API call). Lesson: treat detection as a hint, verify the top
platform against the actual code, and don't audit a gate the code doesn't warrant.

**Gate** (`telegram`, fast) returned 7 checks, including:

- `SKB-TG-SECRETS-0033` — bot token kept secret and rotatable
- `SKB-TG-ACCESS-0037` — admin commands require authorization
- `SKB-TG-WEBHOOK-0034` — webhook verifies `secret_token`

**Investigate** — for the authorization check, grep the handler dispatch and read it:

```
$ grep -nE "is_owner|def handle" bot_handlers.py
222:        if not self.owners.is_owner(sender_id):
242:        if not self.owners.is_owner(getattr(event, "sender_id", None)):
```

Both the message entry point and the callback entry point check the owner and return silently. That
is **pass**, with `bot_handlers.py:222` as evidence — not because a keyword appeared, but because you
read the guard and confirmed it covers every path.

**Find the real issue** by comparing what the code hardens against what it doesn't:

```
$ grep -rnE "chmod" *.py
owner.py:45:        self.path.chmod(0o600)
user_session.py:86: self.session_path.chmod(0o600)
```

The session and owner files are hardened to `600`, but the digest output files and the log file are
written with default permissions — and they contain message content and channel names. That is a real
finding: **inconsistent hardening**, evidenced by the *absence* of `chmod` where its siblings have it.

This is the shape of a good audit: the gate tells you what to look for, and the code tells you where
it actually breaks down. Neither alone is enough.

## Per-platform notes

- **web / api** — check authz on *every* mutating route, not just the ones with "admin" in the name.
  Look for the route that was added later and forgot the guard.
- **telegram** — the session file is the crown jewel (it grants full account control); verify `chmod`
  and that it is git-ignored. Admin commands must check a numeric owner id, not a username.
- **llm** — prompt injection is the headline risk: trace untrusted text (user messages, fetched
  documents) into the prompt, and check that model output is not executed or trusted as instructions.
- **web3** — reentrancy, integer overflow, access control on privileged functions, unchecked external
  calls.
- **mobile / desktop** — insecure storage, IPC exposure, and secrets baked into the binary.

## Choosing `fast` vs `full`

`fast` is the launch gate — the highest-severity, highest-likelihood checks. Use it when the user
wants a pre-ship review. Use `full` for a thorough audit, and budget for it: it is a larger list and
each check needs the same evidence discipline.

## When search returns nothing

Retrieval is lexical and beta (held-out recall@5 ≈ 0.70). A miss does not mean the class is absent.
Reformulate using the wording a card would use (say "hardcoded credential" not "secret in code"),
or fall back to the gate list plus your own knowledge — and flag in the report that the check came
from general knowledge, not from a card.
