"""Load and validate per-secret handling policies from JSON or YAML."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Pattern


POLICY_ACTIONS = frozenset({"allow", "reject", "redact", "log"})
POLICY_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class PolicyConfigurationError(ValueError):
    """Raised when a configured secret policy cannot be read or validated."""


class PolicyRejected(Exception):
    """A request rejected by policy; contains metadata only, never secret values."""

    def __init__(
        self,
        issue_counts: dict[str, int],
        issue_actions: dict[str, str],
        issue_severities: dict[str, str],
    ) -> None:
        super().__init__("Request rejected by secret handling policy")
        self.issue_counts = issue_counts
        self.issue_actions = issue_actions
        self.issue_severities = issue_severities


@dataclass(frozen=True)
class SecretTypePolicy:
    action: str = "redact"
    severity: str = "medium"
    allowlist_values: frozenset[str] = frozenset()
    allowlist_patterns: tuple[Pattern[str], ...] = ()

    def is_allowlisted(self, *values: str) -> bool:
        return any(
            value in self.allowlist_values
            or any(pattern.fullmatch(value) for pattern in self.allowlist_patterns)
            for value in values
            if value
        )


@dataclass(frozen=True)
class SecretPolicy:
    default: SecretTypePolicy = SecretTypePolicy()
    secret_types: dict[str, SecretTypePolicy] | None = None

    def for_type(self, secret_type: str) -> SecretTypePolicy:
        if self.secret_types:
            return self.secret_types.get(secret_type, self.default)
        return self.default


DEFAULT_SECRET_POLICY = SecretPolicy()
_POLICY_CACHE: tuple[tuple[str, int, int, frozenset[str]], SecretPolicy] | None = None


def _parse_setting(
    value: object,
    fallback: SecretTypePolicy | None = None,
    allow_allowlist: bool = True,
) -> SecretTypePolicy:
    if not isinstance(value, dict):
        raise PolicyConfigurationError("policy settings must be objects")
    valid_keys = {"action", "severity"}
    if allow_allowlist:
        valid_keys.add("allowlist")
    if set(value) - valid_keys:
        raise PolicyConfigurationError("policy setting contains unsupported fields")

    action = value.get("action", fallback.action if fallback else "redact")
    severity = value.get("severity", fallback.severity if fallback else "medium")
    if not isinstance(action, str) or action.lower() not in POLICY_ACTIONS:
        raise PolicyConfigurationError("action must be allow, reject, redact, or log")
    if not isinstance(severity, str) or severity.lower() not in POLICY_SEVERITIES:
        raise PolicyConfigurationError("severity must be low, medium, high, or critical")

    allowlist = value.get("allowlist", {})
    if not isinstance(allowlist, dict) or set(allowlist) - {"values", "patterns"}:
        raise PolicyConfigurationError("allowlist must contain only values and patterns")
    values = allowlist.get("values", [])
    patterns = allowlist.get("patterns", [])
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise PolicyConfigurationError("allowlist values must be a list of strings")
    if not isinstance(patterns, list) or not all(
        isinstance(item, str) for item in patterns
    ):
        raise PolicyConfigurationError("allowlist patterns must be a list of strings")

    compiled_patterns = []
    for pattern in patterns:
        try:
            compiled_patterns.append(re.compile(pattern))
        except re.error as exc:
            raise PolicyConfigurationError("allowlist contains an invalid regex") from exc

    return SecretTypePolicy(
        action=action.lower(),
        severity=severity.lower(),
        allowlist_values=frozenset(values),
        allowlist_patterns=tuple(compiled_patterns),
    )


def load_secret_policy(
    path: str | Path, known_types: set[str] | frozenset[str]
) -> SecretPolicy:
    """Load a policy file, rejecting invalid actions, types, and allowlists."""
    policy_path = Path(path).expanduser()
    suffix = policy_path.suffix.lower()
    try:
        content = policy_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PolicyConfigurationError(f"cannot read policy file: {policy_path}") from exc

    if suffix == ".json":
        try:
            raw_policy = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PolicyConfigurationError(f"invalid JSON policy: {policy_path}") from exc
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise PolicyConfigurationError(
                "YAML policy files require PyYAML; install it with `pip install PyYAML`"
            ) from exc
        try:
            raw_policy = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise PolicyConfigurationError(f"invalid YAML policy: {policy_path}") from exc
    else:
        raise PolicyConfigurationError("policy file extension must be .json, .yaml, or .yml")

    if not isinstance(raw_policy, dict) or set(raw_policy) - {"default", "secret_types"}:
        raise PolicyConfigurationError("policy must contain only default and secret_types")

    default = _parse_setting(raw_policy.get("default", {}), allow_allowlist=False)
    type_settings = raw_policy.get("secret_types", {})
    if not isinstance(type_settings, dict):
        raise PolicyConfigurationError("secret_types must be an object")

    parsed_types: dict[str, SecretTypePolicy] = {}
    for secret_type, settings in type_settings.items():
        if not isinstance(secret_type, str) or secret_type not in known_types:
            raise PolicyConfigurationError(f"unknown secret type: {secret_type}")
        parsed_types[secret_type] = _parse_setting(settings, fallback=default)
    return SecretPolicy(default=default, secret_types=parsed_types)


def get_secret_policy(known_types: set[str] | frozenset[str]) -> SecretPolicy:
    """Return the default policy or the cached policy selected by the environment."""
    global _POLICY_CACHE
    configured_path = os.getenv("SECRET_POLICY_PATH")
    if not configured_path:
        return DEFAULT_SECRET_POLICY

    path = Path(configured_path).expanduser().resolve()
    try:
        stat = path.stat()
    except OSError as exc:
        raise PolicyConfigurationError(f"cannot access policy file: {path}") from exc
    cache_key = (str(path), stat.st_mtime_ns, stat.st_size, frozenset(known_types))
    if _POLICY_CACHE is not None and _POLICY_CACHE[0] == cache_key:
        return _POLICY_CACHE[1]

    policy = load_secret_policy(path, known_types)
    _POLICY_CACHE = (cache_key, policy)
    return policy
