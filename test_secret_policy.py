import json
import logging
from collections import Counter

import pytest
from fastapi import HTTPException

from safe_workspace import build_safe_workspace
from secret_policy import PolicyConfigurationError, load_secret_policy
from security_proxy import (
    SanitizeRequest,
    issue_policy_metadata,
    sanitize_endpoint,
    scan_and_sanitize,
)


_KNOWN_TYPES = {"OPENAI_API_KEY", "HIGH_ENTROPY_SECRET"}
_SECRET = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"


def test_json_policy_honors_type_actions_and_exact_regex_allowlists(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "default": {"action": "reject", "severity": "high"},
                "secret_types": {
                    "OPENAI_API_KEY": {
                        "action": "redact",
                        "severity": "critical",
                        "allowlist": {
                            "values": [_SECRET],
                            "patterns": [r"sk-proj-ALLOW-[A-Za-z0-9]{20,}"],
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    policy = load_secret_policy(policy_path, _KNOWN_TYPES)
    pattern_allowed = "sk-proj-ALLOW-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    source = f"one={_SECRET} two={pattern_allowed} three={_SECRET}extra"

    safe_code, counts = scan_and_sanitize(source, policy=policy)

    assert safe_code == f"one={_SECRET} two={pattern_allowed} three=[REDACTED_OPENAI_API_KEY]"
    assert counts == Counter({"OPENAI_API_KEY": 1})
    assert issue_policy_metadata(counts, policy) == (
        {"OPENAI_API_KEY": "redact"},
        {"OPENAI_API_KEY": "critical"},
    )


def test_yaml_log_action_leaves_value_unchanged_and_logs_metadata(tmp_path, caplog):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "default:\n"
        "  action: redact\n"
        "  severity: low\n"
        "secret_types:\n"
        "  OPENAI_API_KEY:\n"
        "    action: log\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    policy = load_secret_policy(policy_path, _KNOWN_TYPES)
    source = f"api_key={_SECRET}"

    with caplog.at_level(logging.ERROR, logger="security_proxy"):
        safe_code, counts = scan_and_sanitize(source, policy=policy)

    assert safe_code == source
    assert counts == Counter({"OPENAI_API_KEY": 1})
    assert "type=OPENAI_API_KEY severity=high count=1" in caplog.text
    assert _SECRET not in caplog.text


def test_allow_action_silently_passes_secret(tmp_path, caplog):
    policy_path = tmp_path / "allow.json"
    policy_path.write_text(
        json.dumps({"default": {"action": "allow", "severity": "low"}}),
        encoding="utf-8",
    )
    policy = load_secret_policy(policy_path, _KNOWN_TYPES)

    with caplog.at_level(logging.DEBUG, logger="security_proxy"):
        safe_code, counts = scan_and_sanitize(_SECRET, policy=policy)

    assert safe_code == _SECRET
    assert not counts
    assert not caplog.records


def test_sanitize_endpoint_reports_log_action_and_severity(tmp_path, monkeypatch):
    policy_path = tmp_path / "log.json"
    policy_path.write_text(
        json.dumps(
            {
                "secret_types": {
                    "OPENAI_API_KEY": {"action": "log", "severity": "high"}
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SECRET_POLICY_PATH", str(policy_path))
    source = f"api_key={_SECRET}"

    response = sanitize_endpoint(SanitizeRequest(code=source))

    assert response.safe_code == source
    assert response.issue_counts == {"OPENAI_API_KEY": 1}
    assert response.issue_actions == {"OPENAI_API_KEY": "log"}
    assert response.issue_severities == {"OPENAI_API_KEY": "high"}
    assert response.total_redactions == 0


def test_reject_applies_only_to_sanitize_endpoint(tmp_path, monkeypatch):
    policy_path = tmp_path / "reject.json"
    policy_path.write_text(
        json.dumps(
            {
                "secret_types": {
                    "OPENAI_API_KEY": {
                        "action": "reject",
                        "severity": "critical",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SECRET_POLICY_PATH", str(policy_path))

    with pytest.raises(HTTPException) as exc_info:
        sanitize_endpoint(SanitizeRequest(code=_SECRET))

    assert exc_info.value.status_code == 422
    assert _SECRET not in str(exc_info.value.detail)
    assert exc_info.value.detail["issue_severities"] == {"OPENAI_API_KEY": "critical"}

    safe_code, counts = scan_and_sanitize(_SECRET)
    assert safe_code == "[REDACTED_OPENAI_API_KEY]"
    assert counts == Counter({"OPENAI_API_KEY": 1})
    assert issue_policy_metadata(counts)[0] == {"OPENAI_API_KEY": "redact"}


def test_workspace_report_distinguishes_log_only_findings(tmp_path, monkeypatch):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "sample.py").write_text(f"api_key={_SECRET}", encoding="utf-8")
    policy_path = tmp_path / "workspace-policy.yaml"
    policy_path.write_text(
        "secret_types:\n"
        "  OPENAI_API_KEY:\n"
        "    action: log\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECRET_POLICY_PATH", str(policy_path))

    report = build_safe_workspace(source_dir, tmp_path / "safe-copy")

    copied_source = (tmp_path / "safe-copy" / "sample.py").read_text(encoding="utf-8")
    workspace_report = (
        tmp_path / "safe-copy" / "SAFE_WORKSPACE_REPORT.md"
    ).read_text(encoding="utf-8")
    assert copied_source == f"api_key={_SECRET}"
    assert report.total_redactions == 0
    assert report.logged == {"sample.py": {"OPENAI_API_KEY": 1}}
    assert "log-only findings (not redacted)" in workspace_report
    assert "OPENAI_API_KEY=1 (high)" in workspace_report
    assert _SECRET not in workspace_report


def test_invalid_policy_types_and_regexes_are_rejected(tmp_path):
    policy_path = tmp_path / "invalid.json"
    policy_path.write_text(
        json.dumps(
            {
                "secret_types": {
                    "OPENAI_API_KEY": {
                        "action": "log",
                        "allowlist": {"patterns": ["["]},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyConfigurationError, match="invalid regex"):
        load_secret_policy(policy_path, _KNOWN_TYPES)
