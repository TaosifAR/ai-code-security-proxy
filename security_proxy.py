"""
security_proxy.py
=================
AI Code Security Proxy & Guardrail - core engine + FastAPI control point.

Flow:  developer code  ->  POST /sanitize  ->  secrets redacted  ->  safe code
(forward `safe_code` to your LLM / agent of choice).

Run the API:
    uvicorn security_proxy:app --reload --port 8000
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import os
import re
import unicodedata
from array import array
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Optional, Pattern

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from secret_policy import (
    PolicyConfigurationError,
    PolicyRejected,
    SecretPolicy,
    get_secret_policy,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("security_proxy")


# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """A detection rule.

    name      -> used in the placeholder: [REDACTED_<name>]
    pattern   -> compiled regex
    group     -> which capture group holds the secret (0 = whole match).
                 Using a group lets us keep context such as `password = `
                 and redact only the value.
    validator -> optional function to reject false positives.
    """

    name: str
    pattern: Pattern[str]
    group: int = 0
    validator: Optional[Callable[[str], bool]] = None


# Values that look like secrets to the regex but are really code, not secrets.
_FALSE_POSITIVE_VALUES = {"none", "null", "true", "false", "undefined", "string", "changeme", "bearer", "basic"}


def _is_real_generic_secret(value: str) -> bool:
    """Skip env lookups, function calls, templates and placeholders."""
    if value.lower() in _FALSE_POSITIVE_VALUES:
        return False
    if re.search(r"[(\[]|environ|getenv|^\$|^\{\{|^<.*>$", value):
        return False
    return True


# ORDER MATTERS: specific rules run before the generic catch-all rule.
RULES: list[Rule] = [
    Rule(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    # OpenAI: sk-..., sk-proj-..., sk-svcacct-...
    Rule("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    # GitHub: classic (ghp_, gho_, ghu_, ghs_, ghr_) and fine-grained (github_pat_)
    Rule(
        "GITHUB_TOKEN",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})"),
    ),
    Rule("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    Rule("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    Rule("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    # HTTP "Authorization: Bearer <token>" headers (only the token is redacted)
    Rule("BEARER_TOKEN", re.compile(r"(?i)\bbearer[ \t]+([A-Za-z0-9\-._~+/]{20,}=*)"), group=1),
    # AWS Access Key ID (AKIA... = long-term, ASIA... = temporary)
    Rule("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    # AWS Secret Access Key: 40 chars, detected by its variable name
    Rule(
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\"']?[ \t]*[:=][ \t]*[\"']?"
            r"([A-Za-z0-9/+=]{40})"
        ),
        group=1,
    ),
    # DB URLs: postgres://user:pass@host/db, mongodb+srv://..., mysql://...
    Rule(
        "DB_CONNECTION_STRING",
        re.compile(
            r"\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql(?:\+pymysql)?|mariadb)"
            r"://[^\s\"'<>]+"
        ),
    ),
    # Generic: api_key = "...", password: "...", client_secret=..., auth_token: ...
    Rule(
        "GENERIC_SECRET",
        re.compile(
            r"(?i)\b[\w.\-]*(?:api[_\-]?key|secret|passwd|password|pwd|token|auth)[\w.\-]*"
            r"[\"']?[ \t]*[:=][ \t]*[\"']?([^\"'\s,;]{4,})[\"']?"
        ),
        group=1,
        validator=_is_real_generic_secret,
    ),
]


@dataclass(frozen=True)
class _Detection:
    start: int
    end: int
    name: str
    value: str


_BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/_-])"
)
_ENTROPY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/_-])"
)
_HEX_HASH_PATTERN = re.compile(r"[0-9a-fA-F]{32,}\Z")
_UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z"
)
_SECRET_TYPES = frozenset(rule.name for rule in RULES) | {"HIGH_ENTROPY_SECRET"}
_SEVERITY_LOG_LEVELS = {
    "low": logging.INFO,
    "medium": logging.WARNING,
    "high": logging.ERROR,
    "critical": logging.CRITICAL,
}


def _normalize_with_mapping(
    text: str,
) -> tuple[str, Optional[tuple[array, array]]]:
    if text.isascii():
        return text, None

    normalized: list[str] = []
    source_starts = array("I")
    source_ends = array("I")
    cluster: list[tuple[int, str]] = []

    def flush_cluster() -> None:
        if not cluster:
            return
        cluster_start = cluster[0][0]
        cluster_end = cluster[-1][0] + 1
        for character in unicodedata.normalize(
            "NFKC", "".join(character for _, character in cluster)
        ):
            normalized.append(character)
            source_starts.append(cluster_start)
            source_ends.append(cluster_end)
        cluster.clear()

    def is_hangul_jamo(character: str) -> bool:
        codepoint = ord(character)
        return (
            0x1100 <= codepoint <= 0x11FF
            or 0xA960 <= codepoint <= 0xA97F
            or 0xD7B0 <= codepoint <= 0xD7FF
        )

    previous_character = ""
    index = 0
    while index < len(text):
        character = text[index]
        if unicodedata.category(character) == "Cf":
            index += 1
            continue
        if character.isascii():
            flush_cluster()
            run_end = index
            while (
                run_end < len(text)
                and text[run_end].isascii()
                and unicodedata.category(text[run_end]) != "Cf"
            ):
                run_end += 1
            safe_end = run_end
            next_index = run_end
            while (
                next_index < len(text)
                and unicodedata.category(text[next_index]) == "Cf"
            ):
                next_index += 1
            if (
                next_index < len(text)
                and unicodedata.combining(text[next_index]) != 0
            ):
                safe_end -= 1
            normalized.extend(text[index:safe_end])
            source_starts.extend(range(index, safe_end))
            source_ends.extend(range(index + 1, safe_end + 1))
            index = safe_end
            if index < run_end:
                cluster.append((index, text[index]))
                previous_character = text[index]
                index += 1
            continue
        if (
            cluster
            and unicodedata.combining(character) == 0
            and not (is_hangul_jamo(previous_character) and is_hangul_jamo(character))
        ):
            flush_cluster()
        cluster.append((index, character))
        previous_character = character
        index += 1
    flush_cluster()
    return "".join(normalized), (source_starts, source_ends)


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < other_end and end > other_start for other_start, other_end in spans)


def _find_rule_detections(
    text: str, excluded_spans: tuple[tuple[int, int], ...] = ()
) -> list[_Detection]:
    detections: list[_Detection] = []
    occupied = list(excluded_spans)
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group)
            start, end = match.span(rule.group)
            if (
                value is None
                or value.startswith("[REDACTED_")
                or (rule.validator and not rule.validator(value))
                or _overlaps(start, end, occupied)
            ):
                continue
            detections.append(_Detection(start, end, rule.name, value))
            occupied.append((start, end))
    return detections


def _entropy(value: str) -> float:
    frequencies = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in frequencies.values()
    )


def _find_entropy_detections(text: str) -> list[_Detection]:
    detections: list[_Detection] = []
    for match in _ENTROPY_PATTERN.finditer(text):
        value = match.group(1)
        if _HEX_HASH_PATTERN.fullmatch(value) or _UUID_PATTERN.fullmatch(value):
            continue
        character_classes = sum(
            (
                any(character.islower() for character in value),
                any(character.isupper() for character in value),
                any(character.isdigit() for character in value),
                any(not character.isalnum() for character in value),
            )
        )
        if character_classes >= 3 and _entropy(value) >= 3.5:
            detections.append(
                _Detection(
                    match.start(1),
                    match.end(1),
                    "HIGH_ENTROPY_SECRET",
                    value,
                )
            )
    return detections


def _find_base64_detections(
    text: str,
) -> tuple[list[_Detection], list[tuple[int, int]]]:
    detections: list[_Detection] = []
    decoded_spans: list[tuple[int, int]] = []
    for match in _BASE64_PATTERN.finditer(text):
        value = match.group(1)
        if len(value) > 8192:
            continue
        try:
            decoded_bytes = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
            decoded_text = decoded_bytes.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        start, end = match.span(1)
        decoded_spans.append((start, end))
        normalized_decoded, _ = _normalize_with_mapping(decoded_text)
        decoded_detections = _find_rule_detections(normalized_decoded)
        if decoded_detections:
            decoded_detection = decoded_detections[0]
        else:
            entropy_detections = _find_entropy_detections(normalized_decoded)
            decoded_detection = entropy_detections[0] if entropy_detections else None
        if decoded_detection is None:
            continue
        detections.append(
            _Detection(start, end, decoded_detection.name, decoded_detection.value)
        )
    return detections, decoded_spans


def _active_policy(policy: Optional[SecretPolicy] = None) -> SecretPolicy:
    return policy if policy is not None else get_secret_policy(_SECRET_TYPES)


def issue_policy_metadata(
    counts: Counter, policy: Optional[SecretPolicy] = None
) -> tuple[dict[str, str], dict[str, str]]:
    active_policy = _active_policy(policy)
    actions = {}
    severities = {}
    for secret_type in counts:
        setting = active_policy.for_type(secret_type)
        actions[secret_type] = "redact" if setting.action == "reject" else setting.action
        severities[secret_type] = setting.severity
    return actions, severities


def _redaction_counts(counts: Counter, actions: dict[str, str]) -> Counter:
    return Counter(
        {
            secret_type: count
            for secret_type, count in counts.items()
            if actions.get(secret_type) == "redact"
        }
    )


def _log_redactions(counts: Counter, actions: dict[str, str], message: str) -> None:
    redactions = _redaction_counts(counts, actions)
    if redactions:
        logger.warning("%s: %s", message, dict(redactions))


# --------------------------------------------------------------------------
# Sanitization
# --------------------------------------------------------------------------
class SecretVault:
    """Remembers which secret hides behind which placeholder (in memory only).

    Placeholders are numbered ([REDACTED_OPENAI_API_KEY_1]) so the original
    values can be restored locally in the LLM's answer. The vault never
    leaves this process and is never sent to the LLM.
    """

    def __init__(self) -> None:
        self._by_value: dict[tuple[str, str], str] = {}
        self._by_placeholder: dict[str, str] = {}
        self._counter: Counter = Counter()

    def placeholder_for(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._by_value:
            self._counter[kind] += 1
            placeholder = f"[REDACTED_{kind}_{self._counter[kind]}]"
            self._by_value[key] = placeholder
            self._by_placeholder[placeholder] = value
        return self._by_value[key]

    def restore(self, text: str) -> str:
        for placeholder, value in self._by_placeholder.items():
            text = text.replace(placeholder, value)
        return text


def scan_and_sanitize(
    code: str,
    vault: Optional[SecretVault] = None,
    policy: Optional[SecretPolicy] = None,
    *,
    enforce_reject: bool = False,
) -> tuple[str, Counter]:
    """Return (safe_code, counts_per_secret_type).

    Normalize text and scan one layer of base64 before applying the secret rules.
    Pass a SecretVault for numbered placeholders and a policy to override the
    environment-selected policy. Reject actions redact unless enforce_reject is set."""
    active_policy = _active_policy(policy)
    normalized, source_map = _normalize_with_mapping(code)
    entropy_detections = _find_entropy_detections(normalized)
    base64_detections, decoded_spans = _find_base64_detections(normalized)
    regex_detections = _find_rule_detections(
        normalized,
        tuple((detection.start, detection.end) for detection in base64_detections),
    )
    occupied = [
        (detection.start, detection.end)
        for detection in base64_detections + regex_detections
    ]
    detections = base64_detections + regex_detections + [
        detection
        for detection in entropy_detections
        if not _overlaps(detection.start, detection.end, occupied)
        and not _overlaps(detection.start, detection.end, decoded_spans)
    ]

    mapped_detections: list[tuple[_Detection, int, int]] = []
    occupied_source: list[tuple[int, int]] = []
    for detection in detections:
        if detection.start >= detection.end:
            continue
        if source_map is None:
            source_start, source_end = detection.start, detection.end
        else:
            source_starts, source_ends = source_map
            source_start = source_starts[detection.start]
            source_end = source_ends[detection.end - 1]
        if _overlaps(source_start, source_end, occupied_source):
            continue
        setting = active_policy.for_type(detection.name)
        if setting.is_allowlisted(code[source_start:source_end], detection.value):
            continue
        if setting.action == "allow":
            continue
        mapped_detections.append((detection, source_start, source_end))
        occupied_source.append((source_start, source_end))

    rule_order = {rule.name: index for index, rule in enumerate(RULES)}
    mapped_detections.sort(
        key=lambda item: (rule_order.get(item[0].name, len(RULES)), item[1])
    )
    replacements: list[tuple[int, int, str]] = []
    counts: Counter = Counter()
    issue_actions: dict[str, str] = {}
    issue_severities: dict[str, str] = {}
    log_counts: Counter = Counter()
    reject_counts: Counter = Counter()
    for detection, start, end in mapped_detections:
        setting = active_policy.for_type(detection.name)
        action = setting.action
        if action == "reject" and not enforce_reject:
            action = "redact"
        counts[detection.name] += 1
        issue_actions[detection.name] = action
        issue_severities[detection.name] = setting.severity
        if setting.action == "log":
            log_counts[detection.name] += 1
        if setting.action == "reject":
            reject_counts[detection.name] += 1
        if action == "redact":
            value = code[start:end]
            placeholder = (
                vault.placeholder_for(detection.name, value)
                if vault
                else f"[REDACTED_{detection.name}]"
            )
            replacements.append((start, end, placeholder))

    for secret_type, count in log_counts.items():
        severity = issue_severities[secret_type]
        logger.log(
            _SEVERITY_LOG_LEVELS[severity],
            "Secret policy log action: type=%s severity=%s count=%d",
            secret_type,
            severity,
            count,
        )
    if enforce_reject and reject_counts:
        raise PolicyRejected(
            dict(counts),
            issue_actions,
            issue_severities,
        )

    safe_code = code
    for start, end, placeholder in sorted(replacements, reverse=True):
        safe_code = f"{safe_code[:start]}{placeholder}{safe_code[end:]}"
    return safe_code, counts


def sanitize_code(code: str) -> tuple[str, list[str]]:
    """
    Redact secrets from `code`.

    Returns:
        safe_code       - code with secrets replaced by [REDACTED_<TYPE>]
        detected_issues - list of detected secret types (unique, in rule order)
    """
    policy = _active_policy()
    safe_code, counts = scan_and_sanitize(code, policy=policy)
    detected_issues = list(counts.keys())
    actions, _ = issue_policy_metadata(counts, policy)
    _log_redactions(counts, actions, "Secrets redacted")
    return safe_code, detected_issues


# --------------------------------------------------------------------------
# FastAPI: the unified control point
# --------------------------------------------------------------------------
app = FastAPI(
    title="AI Code Security Proxy",
    description="Redacts secrets from code before it reaches an LLM / AI agent.",
    version="1.0.0",
)


class SanitizeRequest(BaseModel):
    code: str = Field(..., description="Raw code or text to sanitize")


class SanitizeResponse(BaseModel):
    safe_code: str
    detected_issues: list[str]
    issue_counts: dict[str, int]
    issue_actions: dict[str, str]
    issue_severities: dict[str, str]
    total_redactions: int
    is_clean: bool


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize_endpoint(req: SanitizeRequest) -> SanitizeResponse:
    try:
        policy = _active_policy()
        safe_code, counts = scan_and_sanitize(
            req.code,
            policy=policy,
            enforce_reject=True,
        )
    except PolicyConfigurationError as exc:
        logger.error("Secret policy configuration is invalid")
        raise HTTPException(
            status_code=500,
            detail="Secret policy configuration error",
        ) from exc
    except PolicyRejected as exc:
        logger.warning(
            "Secret policy rejected request: counts=%s severities=%s",
            exc.issue_counts,
            exc.issue_severities,
        )
        raise HTTPException(
            status_code=422,
            detail={
                "message": str(exc),
                "issue_counts": exc.issue_counts,
                "issue_actions": exc.issue_actions,
                "issue_severities": exc.issue_severities,
            },
        ) from exc
    actions, severities = issue_policy_metadata(counts, policy)
    _log_redactions(counts, actions, "Secrets redacted via API")
    # Sanitize-only endpoint. Use POST /chat to also forward the masked text to Claude.
    return SanitizeResponse(
        safe_code=safe_code,
        detected_issues=list(counts.keys()),
        issue_counts=dict(counts),
        issue_actions=actions,
        issue_severities=severities,
        total_redactions=sum(_redaction_counts(counts, actions).values()),
        is_clean=not counts,
    )


# --------------------------------------------------------------------------
# Proxy mode: sanitize -> forward to Claude -> restore placeholders locally
# --------------------------------------------------------------------------
DEFAULT_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")
SYSTEM_PROMPT = (
    "You are a coding assistant. Secrets in the user's message were replaced by "
    "placeholders such as [REDACTED_OPENAI_API_KEY_1]. Keep placeholders exactly as "
    "written, never ask for the real values, and suggest reading secrets from "
    "environment variables."
)


def safe_chat(
    prompt: str,
    code: str = "",
    restore: bool = True,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> dict:
    """Mask secrets in prompt+code, send ONLY the masked text to Claude, and
    (optionally) put the original values back into the answer locally."""
    message = f"{prompt}\n\n```\n{code}\n```" if code.strip() else prompt
    vault = SecretVault()
    policy = _active_policy()
    safe_message, counts = scan_and_sanitize(message, vault, policy=policy)
    actions, severities = issue_policy_metadata(counts, policy)
    _log_redactions(counts, actions, "Secrets redacted before LLM call")

    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set (env var or sidebar field).")
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("Missing dependency: run `pip install anthropic`.") from exc

    client = anthropic.Anthropic(api_key=key)
    response = client.messages.create(
        model=model or DEFAULT_MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": safe_message}],
    )
    reply = "".join(b.text for b in response.content if getattr(b, "type", "") == "text")
    return {
        "sanitized_message": safe_message,  # exactly what the LLM saw
        "reply": vault.restore(reply) if restore else reply,
        "detected_issues": list(counts.keys()),
        "issue_counts": dict(counts),
        "issue_actions": actions,
        "issue_severities": severities,
        "total_redactions": sum(_redaction_counts(counts, actions).values()),
        "restored": restore,
    }


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="Your question for the AI")
    code: str = Field("", description="Code that may contain secrets")
    restore: bool = Field(True, description="Restore placeholders in the answer locally")


@app.post("/chat")
def chat_endpoint(req: ChatRequest) -> dict:
    try:
        return safe_chat(req.prompt, req.code, req.restore)
    except PolicyConfigurationError as exc:
        logger.error("Secret policy configuration is invalid")
        raise HTTPException(status_code=500, detail="Secret policy configuration error") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # never leak details (or secrets) from upstream errors
        logger.error("Upstream LLM call failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Upstream LLM request failed")
