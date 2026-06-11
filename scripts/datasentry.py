#!/usr/bin/env python3
"""DataSentry — deterministic secret redaction for Claude Code.

Runs as a Claude Code hook (UserPromptSubmit, PostToolUse). Reads the hook
payload from stdin, scans for secrets using the bundled rule set plus any
user-defined rules, and either blocks the prompt or replaces the tool output
before the model sees it.

Stdlib only — this script must run anywhere `python3` exists.
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = PLUGIN_ROOT / "rules" / "rules.json"

# Severity tiers activated per protection level. "paranoid" additionally
# enables rules flagged "noisy" (high false-positive patterns).
LEVEL_SEVERITIES = {
    "off": set(),
    "essential": {"critical"},
    "standard": {"critical", "high"},
    "strict": {"critical", "high", "medium", "low"},
    "paranoid": {"critical", "high", "medium", "low"},
}

DEFAULT_CONFIG = {
    "level": "standard",
    "categories": {},
    "custom_rules": [],
    "allowlist": [],
    "fail_mode": "closed",
    "audit_log": True,
}

# Values matching any of these are treated as documentation/test data, not
# real secrets, and are never redacted.
DEFAULT_ALLOWLIST = [
    r"(?i)example|sample|placeholder|dummy|changeme|change-me|your[-_]",
    r"(?i)x{4,}|<[a-z_-]+>|\$\{[A-Za-z_]+\}",
]


def state_dir() -> Path:
    override = os.environ.get("DATASENTRY_HOME")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "datasentry"


def load_config() -> dict:
    path = os.environ.get("DATASENTRY_CONFIG") or str(state_dir() / "config.json")
    config = dict(DEFAULT_CONFIG)
    try:
        with open(path, encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            config.update(user)
    except (OSError, ValueError):
        pass  # missing or malformed config -> defaults
    if config.get("level") not in LEVEL_SEVERITIES:
        config["level"] = "standard"
    return config


def load_rules(config: dict) -> list:
    """Compile the active rule set for the configured protection level."""
    level = config["level"]
    if level == "off":
        return []
    active_severities = LEVEL_SEVERITIES[level]
    include_noisy = level == "paranoid"
    category_overrides = config.get("categories") or {}

    with open(RULES_PATH, encoding="utf-8") as fh:
        ruleset = json.load(fh)

    raw = list(ruleset.get("rules", []))
    for custom in config.get("custom_rules") or []:
        raw.append(
            {
                "id": custom.get("id", "custom"),
                "name": custom.get("name", custom.get("id", "custom")),
                "category": custom.get("category", "custom"),
                "severity": custom.get("severity", "critical"),
                "pattern": custom["pattern"],
                "noisy": False,
            }
        )

    compiled = []
    for rule in raw:
        if rule.get("severity") not in active_severities:
            continue
        if rule.get("noisy") and not include_noisy:
            continue
        if category_overrides.get(rule.get("category")) is False:
            continue
        try:
            compiled.append((rule, re.compile(rule["pattern"])))
        except re.error:
            continue  # one bad pattern must not disable the engine
    return compiled


def compile_allowlist(config: dict) -> list:
    patterns = DEFAULT_ALLOWLIST + list(config.get("allowlist") or [])
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


def placeholder(rule_id: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:4]
    return f"[DS:{rule_id}:{digest}]"


def scan(text: str, rules: list, allowlist: list):
    """Return (redacted_text, {rule_id: hit_count})."""
    hits = {}

    for rule, regex in rules:
        def _sub(match, _rule=rule):
            value = match.group(0)
            if any(a.search(value) for a in allowlist):
                return value
            hits[_rule["id"]] = hits.get(_rule["id"], 0) + 1
            return placeholder(_rule["id"], value)

        text = regex.sub(_sub, text)
    return text, hits


def scan_obj(obj, rules: list, allowlist: list, hits: dict):
    """Recursively redact every string inside a JSON-ish structure."""
    if isinstance(obj, str):
        redacted, h = scan(obj, rules, allowlist)
        for k, v in h.items():
            hits[k] = hits.get(k, 0) + v
        return redacted
    if isinstance(obj, list):
        return [scan_obj(item, rules, allowlist, hits) for item in obj]
    if isinstance(obj, dict):
        return {k: scan_obj(v, rules, allowlist, hits) for k, v in obj.items()}
    return obj


def audit(config: dict, payload: dict, hits: dict, action: str):
    if not config.get("audit_log") or not hits:
        return
    try:
        directory = state_dir()
        directory.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "session_id": payload.get("session_id"),
            "event": payload.get("hook_event_name"),
            "tool_name": payload.get("tool_name"),
            "action": action,
            "rules": hits,  # rule ids and counts only — never secret values
        }
        with open(directory / "audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def rule_names(hits: dict, rules: list) -> str:
    by_id = {rule["id"]: rule["name"] for rule, _ in rules}
    return ", ".join(sorted(by_id.get(rid, rid) for rid in hits))


def handle_user_prompt(payload: dict, rules: list, allowlist: list, config: dict):
    prompt = payload.get("prompt") or ""
    _, hits = scan(prompt, rules, allowlist)
    if not hits:
        return
    audit(config, payload, hits, "blocked-prompt")
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": (
                    "🛡️  DataSentry: PROMPT BLOCKED — detected "
                    f"{rule_names(hits, rules)}.\n"
                    "Your message was NOT sent to the model. Remove the "
                    "secret (or swap in a placeholder like <MY_API_KEY>) and "
                    "resubmit.\n"
                    "Tune protection with /datasentry, or disable with "
                    "/datasentry off."
                ),
            }
        )
    )


def handle_post_tool_use(payload: dict, rules: list, allowlist: list, config: dict):
    response = payload.get("tool_response")
    if response is None:
        return
    hits = {}
    # Preserve the original response type: structured tool responses (Read,
    # Bash, ...) must be replaced with the same shape or the harness drops
    # the update silently.
    replacement = scan_obj(response, rules, allowlist, hits)
    if not hits:
        return
    audit(config, payload, hits, "redacted-output")
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": replacement,
                    "additionalContext": (
                        "DataSentry redacted secrets from this tool output "
                        f"({rule_names(hits, rules)}). Placeholders like "
                        "[DS:rule:hash] are stable per value — preserve them "
                        "verbatim when editing files."
                    ),
                }
            }
        )
    )


_EVENT = "unknown"


def main() -> int:
    global _EVENT
    payload = json.load(sys.stdin)
    _EVENT = event = payload.get("hook_event_name", "")
    config = load_config()
    if config["level"] == "off":
        return 0
    rules = load_rules(config)
    if not rules:
        return 0
    allowlist = compile_allowlist(config)

    if event == "UserPromptSubmit":
        handle_user_prompt(payload, rules, allowlist, config)
    elif event == "PostToolUse":
        handle_post_tool_use(payload, rules, allowlist, config)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — fail-mode boundary
        try:
            fail_open = load_config().get("fail_mode") == "open"
        except Exception:  # noqa: BLE001
            fail_open = False
        if fail_open:
            sys.exit(0)
        # Fail-closed: suppress the data rather than risk leaking it.
        err = f"{type(exc).__name__}: {exc}"
        if _EVENT == "PostToolUse":
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": (
                        "[DataSentry] Redaction engine error — tool output "
                        f"suppressed (fail-closed): {err}. Set fail_mode to "
                        "'open' in ~/.claude/datasentry/config.json to bypass."
                    ),
                }
            }
        else:
            out = {
                "decision": "block",
                "reason": (
                    "DataSentry engine error — prompt blocked (fail-closed): "
                    f"{err}. Set fail_mode to 'open' in "
                    "~/.claude/datasentry/config.json to bypass."
                ),
            }
        print(json.dumps(out))
        sys.exit(0)
