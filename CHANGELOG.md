# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Curated rule set (`rules/rules.json`): 58 rules ported and hardened from the Warp ADE Enterprise Privacy Rules, with id/name/category/severity metadata and `noisy` flags.
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
