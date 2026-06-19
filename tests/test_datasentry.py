#!/usr/bin/env python3
"""Tests for the DataSentry redaction hook.

Run: python3 tests/test_datasentry.py
Invokes the hook script as a subprocess, exactly as Claude Code does.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "datasentry.py"


def run_hook(payload, level="standard", extra_config=None):
    """Feed a hook payload to the script, return parsed JSON output or None."""
    config = {"level": level, "audit_log": False, "fail_mode": "closed"}
    if extra_config:
        config.update(extra_config)
    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "config.json")
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh)
        env = dict(os.environ, DATASENTRY_CONFIG=config_path, DATASENTRY_HOME=tmp)
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
    if proc.returncode != 0:
        raise AssertionError(f"hook exited {proc.returncode}: {proc.stderr}")
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def post_tool_use(response, tool_name="Bash"):
    return {
        "hook_event_name": "PostToolUse",
        "session_id": "test",
        "tool_name": tool_name,
        "tool_input": {"command": "test"},
        "tool_response": response,
    }


def user_prompt(prompt):
    return {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "test",
        "prompt": prompt,
    }


class RedactionTests(unittest.TestCase):
    def assert_redacted(self, result, secret, rule_id=None):
        self.assertIsNotNone(result, "expected redaction output, got none")
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn(secret, out, "secret leaked through redaction")
        self.assertIn("[DS:", out, "placeholder missing")
        if rule_id:
            self.assertIn(f"[DS:{rule_id}:", out)

    def test_aws_access_key_redacted(self):
        secret = "AKIAQQQQQQQQQQQQQQQQ"
        result = run_hook(post_tool_use(f"env output:\nAWS_KEY={secret}\n"))
        self.assert_redacted(result, secret, "aws-access-key-id")

    def test_github_token_redacted(self):
        secret = "ghp_" + "A1b2C3d4" * 5  # 40 chars after prefix
        result = run_hook(post_tool_use(f"remote: {secret}@github.com"))
        self.assert_redacted(result, secret)

    def test_snyk_token_redacted(self):
        # Snyk tokens are UUIDs; only redact when anchored to a snyk key name.
        token = "11111111-2222-4333-8444-555555555555"
        result = run_hook(post_tool_use(f"SNYK_TOKEN={token}"))
        self.assert_redacted(result, token, "snyk-token")
        # A bare UUID with no snyk context must not trip this rule.
        self.assertIsNone(run_hook(post_tool_use(f"request id {token}")))

    def test_anthropic_key_blocks_prompt(self):
        secret = "sk-ant-api03-" + "Qq7Rr8Ss9" * 5
        result = run_hook(user_prompt(f"use this key: {secret}"))
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")
        self.assertNotIn(secret, result["reason"])

    def test_clean_prompt_passes(self):
        self.assertIsNone(run_hook(user_prompt("refactor the auth module")))

    def test_clean_output_untouched(self):
        clean = "Compiled 14 modules in 2.3s\nversion 1.2.3\nHTTP 404 on /health\n$1,234.56 total"
        self.assertIsNone(run_hook(post_tool_use(clean)))

    def test_git_sha_not_redacted_at_standard(self):
        sha = "5dee91a0c4b7e2f8a1d3c6b9e0f2a4d6c8b0e1f3"
        self.assertIsNone(run_hook(post_tool_use(f"commit {sha} (HEAD -> main)")))

    def test_ip_not_redacted_at_standard(self):
        self.assertIsNone(run_hook(post_tool_use("listening on 192.168.1.10:8080")))

    def test_ip_redacted_at_paranoid(self):
        result = run_hook(post_tool_use("listening on 192.168.1.10:8080"), level="paranoid")
        self.assert_redacted(result, "192.168.1.10")

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        result = run_hook(post_tool_use(f"Set-Cookie: token={jwt}"))
        self.assert_redacted(result, jwt, "jwt")

    def test_db_uri_redacted(self):
        uri = "postgresql://airi:s3cr3tpass@db.internal:5432/airi"
        result = run_hook(post_tool_use(f"DATABASE_URL={uri}"))
        self.assertIsNotNone(result)
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn("s3cr3tpass", out)

    def test_pem_block_redacted(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq\n-----END RSA PRIVATE KEY-----"
        result = run_hook(post_tool_use(f"cat id_rsa:\n{pem}\n"))
        self.assert_redacted(result, "MIIEowIBAAKCAQEA7bq", "pem-private-key")

    def test_ssn_valid_redacted_invalid_kept(self):
        result = run_hook(post_tool_use("ssn: 123-45-6789"))
        self.assert_redacted(result, "123-45-6789", "ssn")
        self.assertIsNone(run_hook(post_tool_use("serial 000-12-3456")))

    def test_dotenv_multiple_secrets(self):
        env_file = (
            "API_KEY=sk-proj-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0PpOoNn\n"
            "DB_PASSWORD=hunter2hunter2\n"
            "DEBUG=true\n"
        )
        result = run_hook(post_tool_use(env_file, tool_name="Read"))
        self.assertIsNotNone(result)
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn("hunter2hunter2", out)
        self.assertNotIn("Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0PpOoNn", out)
        self.assertIn("DEBUG=true", out, "non-secret lines must survive")

    def test_allowlist_skips_doc_examples(self):
        self.assertIsNone(
            run_hook(post_tool_use("api_key=your_example_key_goes_here_123456"))
        )

    def test_level_off_disables_everything(self):
        secret = "AKIAQQQQQQQQQQQQQQQQ"
        self.assertIsNone(run_hook(post_tool_use(secret), level="off"))

    def test_dict_response_redacted_preserving_shape(self):
        response = {"stdout": "token: ghp_" + "Z9y8X7w6" * 5, "stderr": "", "exit_code": 0}
        result = run_hook(post_tool_use(response))
        self.assertIsNotNone(result)
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        # The harness silently drops updatedToolOutput if its type does not
        # match the original tool_response — a dict must stay a dict.
        self.assertIsInstance(out, dict)
        self.assertNotIn("ghp_Z9y8X7w6", out["stdout"])
        self.assertIn("[DS:github-token:", out["stdout"])
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["stderr"], "")

    def test_custom_rule(self):
        result = run_hook(
            post_tool_use("internal id ACME-SEC-12345"),
            extra_config={
                "custom_rules": [
                    {"id": "acme-id", "name": "ACME ID", "pattern": "ACME-SEC-\\d{5}"}
                ]
            },
        )
        self.assert_redacted(result, "ACME-SEC-12345", "acme-id")

    def test_category_override_disables(self):
        result = run_hook(
            post_tool_use("ssn: 123-45-6789"),
            extra_config={"categories": {"pii": False}},
        )
        self.assertIsNone(result)

    def test_placeholder_stable_per_value(self):
        secret = "AKIAQQQQQQQQQQQQQQQQ"
        r1 = run_hook(post_tool_use(f"a {secret}"))
        r2 = run_hook(post_tool_use(f"b {secret}"))
        p1 = r1["hookSpecificOutput"]["updatedToolOutput"].split()[1]
        p2 = r2["hookSpecificOutput"]["updatedToolOutput"].split()[1]
        self.assertEqual(p1, p2)

    def test_malformed_stdin_fails_closed(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="not json at all",
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out.get("decision"), "block")

    def test_prose_form_api_key_blocked(self):
        # "my api key is X" — spaced compound, "is" separator. Field-tested gap.
        result = run_hook(user_prompt("lets test, my api key is sk-1234asdf989j923j982j89"))
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")

    def test_prose_short_values_not_blocked(self):
        # "api key is required/invalid" must never trip the prose separator.
        self.assertIsNone(run_hook(user_prompt("the api key is required for auth")))
        self.assertIsNone(run_hook(user_prompt("my password is wrong")))

    def test_authorization_header_redacted(self):
        result = run_hook(
            post_tool_use('curl -H "Authorization: Bearer abc123def456ghi789jkl"')
        )
        self.assertIsNotNone(result)
        self.assertNotIn(
            "abc123def456ghi789jkl",
            result["hookSpecificOutput"]["updatedToolOutput"],
        )


def seed_audit(home):
    """Write a known audit.jsonl into a DATASENTRY_HOME directory."""
    rows = [
        {"ts": "2026-06-17T00:00:00+00:00", "session_id": "s1",
         "action": "redacted-output", "rules": {"aws-access-key-id": 2}},
        {"ts": "2026-06-17T00:01:00+00:00", "session_id": "s1",
         "action": "blocked-prompt", "rules": {"jwt": 1}},
        {"ts": "2026-06-17T00:02:00+00:00", "session_id": "s2",
         "action": "redacted-output", "rules": {"aws-access-key-id": 1}},
    ]
    with open(os.path.join(home, "audit.jsonl"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def run_stats(home):
    env = dict(os.environ, DATASENTRY_HOME=home)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--stats"],
        capture_output=True, text=True, env=env, timeout=30,
    )


def run_session_end(home, session_id):
    payload = {"hook_event_name": "SessionEnd", "session_id": session_id}
    env = dict(os.environ, DATASENTRY_HOME=home)
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30,
    )


class AuditSummaryTests(unittest.TestCase):
    def test_stats_summarizes_whole_log(self):
        """Expected: --stats rolls up totals and top rules across all sessions."""
        with tempfile.TemporaryDirectory() as tmp:
            seed_audit(tmp)
            proc = run_stats(tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("4 secrets caught", proc.stdout)  # 2 + 1 + 1
            self.assertIn("aws-access-key-id", proc.stdout)
            self.assertIn("jwt", proc.stdout)
            self.assertIn("2 sessions", proc.stdout)

    def test_stats_empty_log(self):
        """Edge: no audit file yet still exits clean with a helpful message."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_stats(tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("no audit entries", proc.stdout.lower())

    def test_session_end_counts_only_this_session(self):
        """Expected: SessionEnd tallies only the ending session's entries."""
        with tempfile.TemporaryDirectory() as tmp:
            seed_audit(tmp)
            proc = run_session_end(tmp, "s1")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("caught 3 secret(s)", proc.stdout)  # s1: 2 aws + 1 jwt
            self.assertIn("1 prompt(s) blocked", proc.stdout)
            self.assertNotIn("s2", proc.stdout)

    def test_session_end_silent_for_unknown_session(self):
        """Failure/edge: a session with no entries prints nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            seed_audit(tmp)
            proc = run_session_end(tmp, "never-logged")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
