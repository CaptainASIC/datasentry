# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-20

### Added

- `snyk-token` rule (critical, devops) — redacts Snyk API tokens. Snyk tokens
  are bare UUIDs, so the rule anchors to the `snyk*token` key name to catch
  `SNYK_TOKEN=<uuid>` assignments without tripping on unrelated UUIDs.

## [0.2.0] - 2026-06-17

### Changed

- **Command is now `/datasentry` instead of `/datasentry:datasentry`.** Moved
  the command from `commands/datasentry.md` to a root `SKILL.md` with a
  `name: datasentry` frontmatter field. A plugin's root skill is its default,
  unnamespaced skill; only skills under `commands/`/`skills/` carry the
  `plugin:` prefix.
- Added `displayName: "DataSentry"` to `plugin.json` (shown in the `/plugin`
  picker; ignored by clients older than Claude Code v2.1.143).

### Added

- `/datasentry stats` — all-time audit summary (`--stats` mode on the engine):
  total secrets caught, redactions vs blocks, session count, time window, and
  the top rules tripped. Rule IDs and counts only — never secret values.
- `SessionEnd` hook prints a one-line per-session tally of what was redacted
  and blocked, for at-a-glance trust.
- CI now runs `claude plugin validate . --strict` to catch manifest and
  frontmatter schema regressions.

## [0.1.4] - 2026-06-11

### Changed

- Attribution corrected: the regex ruleset was authored by Captain ASIC for
  use with Warp ADE's custom-pattern settings — it is not Warp's ruleset.
  Only the redaction *approach* is inspired by Warp's feature. README and
  rules.json wording fixed.

## [0.1.3] - 2026-06-11

### Added

- `LICENSE` file (GPL-3.0 full text) — was declared but missing.
- SessionStart hook warns loudly when `python3` is absent from PATH —
  previously the hooks failed silently and redaction was inactive while
  appearing installed.
- GitHub Actions CI: manifest validation, rule compilation, full test suite.

### Fixed

- Prose-form secret mentions now detected: "my api key is sk-..." — spaced
  compounds ("api key" not just "api_key") and "is"/"was" separators in the
  generic API-key and password rules. Field-tested gap from first user test.

## [0.1.2] - 2026-06-11

### Fixed

- **Tool-output redaction silently failed for structured tool responses**
  (Read, Bash, and most built-in tools). The engine replaced structured
  `tool_response` objects with a JSON-dumped string; the harness drops
  `updatedToolOutput` when its type does not match the original response, so
  detection fired (additionalContext delivered) but the raw secret still
  reached the model. The replacement now preserves the original response
  shape. Verified end-to-end with live headless sessions on both Read and
  Bash paths.

## [0.1.1] - 2026-06-11

### Changed

- Blocked-prompt message made far more prominent (🛡️ banner, explicit "your
  message was NOT sent to the model", recovery instructions) — field testing
  showed users read a silent block as the app hanging.

## [0.1.0] - 2026-06-11

### Added

- Claude Code plugin: deterministic secret redaction via hooks.
  - `PostToolUse` hook redacts secrets from all tool outputs (`updatedToolOutput`) before the model sees them.
  - `UserPromptSubmit` hook blocks prompts containing secrets.
- Curated rule set (`rules/rules.json`): 58 rules ported and hardened from Captain ASIC's original enterprise privacy ruleset (written for Warp ADE), with id/name/category/severity metadata and `noisy` flags.
- Protection levels: `off`, `essential`, `standard` (default), `strict`, `paranoid`.
- `/datasentry` command: interactive wizard, `status`, `test`, `level <name>`, `off`.
- Config at `~/.claude/datasentry/config.json`: level, category overrides, custom rules, allowlist, fail mode (`closed` default), audit log.
- Stable per-value placeholders `[DS:<rule-id>:<hash4>]`.
- Audit log (rule IDs and counts only, never values) at `~/.claude/datasentry/audit.jsonl`.
- Marketplace manifest — install with `/plugin marketplace add CaptainASIC/datasentry`.
- Test suite: 21 subprocess-level tests (`tests/test_datasentry.py`).

### Changed

- Original Warp regex ruleset document moved from `README.md` to `docs/WARP.md`.
- Repository renamed `datasentry-mcp` → `datasentry`.

### Excluded (deliberately)

- Standalone CVV/MRN/dollar-amount/Base64/log-level patterns and proximity-based detection from the original document — unacceptable false-positive rates for an agentic coding tool. Rationale table in README.
