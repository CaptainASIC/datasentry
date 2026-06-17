---
name: datasentry
description: Configure DataSentry secret redaction (level, categories, fail mode, audit log)
argument-hint: "[status|stats|test|level <name>|off]"
allowed-tools: ["Read", "Write", "Bash", "AskUserQuestion", "Glob"]
---

You are configuring DataSentry, the secret-redaction plugin. Its config lives at
`~/.claude/datasentry/config.json` and is read by a hook on every prompt and
tool call, in every session. The bundled rules live at
`${CLAUDE_PLUGIN_ROOT}/rules/rules.json` (relative to this plugin's install
directory; find it with Glob if needed).

Arguments given: "$ARGUMENTS"

## Dispatch on arguments

- **`status`** — Read the config file (if missing, report defaults: level
  `standard`, fail_mode `closed`, audit_log `true`). Read the rules file and
  report: current level, how many rules are active at that level, category
  overrides, custom rules, allowlist entries, and the last 5 entries of
  `~/.claude/datasentry/audit.jsonl` if it exists. Concise table.
- **`test`** — Run a live check: pipe a synthetic PostToolUse payload
  containing a FAKE secret (e.g. `AKIAIOSFODNN7EXAMPLE0` — note: must NOT
  contain the word "example" since allowlisted; use `[DS:aws-access-key-id:2599]`)
  through the script with Bash and confirm it emits `updatedToolOutput` with a
  `[DS:...]` placeholder. Report pass/fail with the actual output.
- **`stats`** — Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/datasentry.py" --stats`
  with Bash and relay its output verbatim. It summarizes the whole audit log:
  total secrets caught, redactions vs blocks, session count, time window, and
  the top rules tripped (rule IDs and counts only — never values).
- **`level <name>`** or **`off`** — Set `level` directly (one of: off,
  essential, standard, strict, paranoid), preserving other config keys. Write
  the file and confirm.
- **No arguments** — Run the interactive wizard below.

## Interactive wizard

1. Read the current config (defaults if missing).
2. Use AskUserQuestion with these questions (mark current values in labels):

   **Protection level** (single choice):
   - `essential` — Critical only: cloud/API keys, tokens, private keys, credentialed DB URIs. Lowest false-positive rate.
   - `standard` (Recommended) — + passwords, auth headers, SSNs, payment cards, CI/CD and container secrets.
   - `strict` — + PII assignments (email/phone/DOB), healthcare and financial IDs, session IDs.
   - `paranoid` — Everything, including noisy patterns (all IPs, all emails, MAC addresses, crypto addresses). Expect false positives that may hinder normal work.

   **Disable any categories?** (multiSelect; offer the categories present in
   rules.json: cloud, devops, saas, ai, credentials, database, auth, pii,
   financial, healthcare, government, enterprise, network, web3)

   **Fail mode** (single choice):
   - `closed` (Recommended) — engine error suppresses the data. Safer.
   - `open` — engine error lets data through unredacted. More convenient.

   **Audit log** (on/off) — log rule IDs and counts (never secret values) to
   `~/.claude/datasentry/audit.jsonl`.

3. Write the merged config to `~/.claude/datasentry/config.json` (create the
   directory if needed). Preserve any existing `custom_rules` and `allowlist`
   keys — the wizard must never drop them.
4. Confirm with a one-line summary and remind the user: changes apply to all
   new prompts and tool calls immediately (hooks re-read config every
   invocation); no restart needed.

## Notes

- Never print real secrets while testing. Use obviously fake values.
- If the user asks for a custom rule, append to `custom_rules` as
  `{"id": "...", "name": "...", "pattern": "...", "severity": "critical"}`
  after validating the regex compiles (`python3 -c "import re; re.compile(...)"`)
  and warning about false-positive blast radius if the pattern is broad.
