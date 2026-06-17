# DataSentry

**Warp-style secret redaction for Claude Code.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/Version-0.2.0-green.svg)](https://github.com/CaptainASIC/datasentry)

DataSentry is a Claude Code plugin that keeps secrets out of your model context. It runs as a deterministic hook — not a model instruction — on every prompt and every tool call, in every session:

- **Tool outputs are redacted before the model sees them.** When `Read`, `Bash`, `Grep`, or any MCP tool returns content containing a secret, the hook replaces it with a stable placeholder (`[DS:aws-access-key-id:3fa1]`) before it enters the context window.
- **Prompts containing secrets are blocked.** Claude Code hooks cannot rewrite prompt text, so if you paste a live credential, DataSentry blocks the prompt, tells you which rule tripped, and asks you to resubmit without it.
- **Configured once, enforced everywhere.** Settings live in `~/.claude/datasentry/config.json` and are re-read on every hook invocation — they apply to all projects and all sessions, like Warp's secret redaction.

## Install

```
/plugin marketplace add CaptainASIC/datasentry
/plugin install datasentry@datasentry
```

Requires `python3` on PATH (stdlib only, no dependencies). **If `python3` is missing, the hooks cannot run and redaction is silently inactive** — a SessionStart check warns you loudly in every session where that is the case.

## Configure

```
/datasentry            # interactive wizard
/datasentry status     # current level, active rule count, recent audit entries
/datasentry stats      # all-time audit summary: totals, top rules, time window
/datasentry test       # live end-to-end check with a fake secret
/datasentry level strict
/datasentry off
```

### Protection levels

| Level | Active rules | False-positive risk |
|---|---|---|
| `off` | none | — |
| `essential` | Critical only: cloud/API keys (AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Google, npm, PyPI, Hugging Face, Vault…), PEM private keys, JWTs, credentialed DB URIs, seed phrases | Very low |
| `standard` *(default)* | + password/API-key assignments, Authorization headers, SSNs, payment cards, CI/CD and container secrets | Low |
| `strict` | + PII assignments (email/phone/DOB), healthcare and financial identifiers, session IDs, license keys | Moderate |
| `paranoid` | Everything, including noisy patterns: all IPv4 addresses, all email addresses, MAC addresses, crypto addresses | High — will interfere with normal dev work |

Per-category overrides (`"categories": {"pii": false}`), custom rules, and a value allowlist are supported in the config file — see `/datasentry`.

### Config file

`~/.claude/datasentry/config.json`:

```json
{
  "level": "standard",
  "categories": {},
  "custom_rules": [
    {"id": "acme-id", "name": "ACME internal ID", "pattern": "ACME-SEC-\\d{5}", "severity": "critical"}
  ],
  "allowlist": ["(?i)test-fixture"],
  "fail_mode": "closed",
  "audit_log": true
}
```

- `fail_mode: "closed"` (default) — if the redaction engine itself errors, the data is suppressed rather than passed through. Set `"open"` to prefer availability over safety.
- `audit_log` — appends rule IDs and hit counts (never secret values) to `~/.claude/datasentry/audit.jsonl`.

## How it works

| Surface | Mechanism |
|---|---|
| Tool results (Read, Bash, Grep, MCP, …) | `PostToolUse` hook replaces the result via `updatedToolOutput` before the model sees it |
| User prompts | `UserPromptSubmit` hook blocks the prompt (hooks cannot rewrite prompts) |
| Session summary | `SessionEnd` hook prints a one-line tally of what was caught this session |
| Persistence | Plugin hooks are merged into every session; config is read per invocation |

Placeholders are stable per secret value (`sha1[:4]`), so the same key always redacts to the same token — the model can reference and preserve them when editing files without ever seeing the value.

## Rule set

58 curated rules in [rules/rules.json](rules/rules.json), ported and hardened from [Captain ASIC's original enterprise privacy ruleset](docs/WARP.md) — hand-written regex patterns this repo previously published for use with Warp ADE's custom secret-redaction settings. Each rule has an id, name, category, severity, and optional `noisy` flag.

Several patterns from the original ruleset were **deliberately excluded** because they would destroy usability:

| Excluded pattern | Why |
|---|---|
| Standalone CVV `\b[0-9]{3,4}\b` | Matches every 3–4 digit number (HTTP 404, port numbers, years) |
| Standalone MRN `\b[0-9]{5,}\b` | Matches every number ≥ 5 digits (timestamps, PIDs, line counts) |
| Dollar amounts `\$[0-9]{1,3}(,...)` | Matches every price in every output |
| Generic Base64 blocks | Matches most of modern tool output |
| RFC 5322 email (unanchored) | Redacts every email everywhere — gated to `paranoid` as `email-any` instead |
| Proximity patterns (`password.{0,50}...`) | Overcapture: redacts 50 chars of innocent context per hit |
| Log-level markers `\[(DEBUG\|INFO\|...)\]` | Not a secret |

## Honest limitations

- **Regex redaction is hygiene, not a security boundary.** It reduces accidental transmission of credentials to the API. It will not stop deliberate exfiltration or secrets in formats the rules don't cover.
- **The model's own output is not filtered.** Claude Code exposes no hook between the model and the API transport. If a secret enters context through a path hooks don't cover, redaction can't remove it retroactively. Transport-level guarantees require an `ANTHROPIC_BASE_URL` proxy (planned, phase 2).
- **Tool inputs are not scanned.** Tool inputs are written by the model, so by the time they exist the model has already seen their content — redacting them would protect nothing.
- **Contextual patterns have false positives.** `password = somelongvariablename` looks identical to `password = realpassword1` to a regex. Warp has the same limitation. Tune with `allowlist` and category overrides.
- **Redaction can blind the agent.** If Claude needs to *edit* a file whose values are redacted, it sees placeholders, not values. Placeholders are stable so edits can preserve them, but workflows that genuinely require the secret value will not work at that protection level.

## Development

```
python3 tests/test_datasentry.py    # 27 tests, subprocess-level, no deps
```

## Roadmap (phase 2)

- `ANTHROPIC_BASE_URL` redacting proxy for transport-layer guarantees
- Reversible placeholder map (local vault) for write-back workflows
- Entropy-based detection to complement regex
- Compiled (Rust) scanner if hook latency becomes measurable
- Managed-settings deployment guide for org-wide enforcement

## Credits & License

GPL-3.0 © Captain ASIC. Redaction approach inspired by [Warp](https://www.warp.dev/)'s secret redaction feature; all regex rules authored by Captain ASIC. The original hand-written ruleset (written for Warp ADE's custom-pattern settings) is preserved at [docs/WARP.md](docs/WARP.md).
