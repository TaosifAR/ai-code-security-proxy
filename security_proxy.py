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

import logging
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Optional, Pattern

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

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
_FALSE_POSITIVE_VALUES = {"none", "null", "true", "false", "undefined", "string", "changeme"}


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
    # AWS Access Key ID (AKIA... = long-term, ASIA... = temporary)
    Rule("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    # AWS Secret Access Key: 40 chars, detected by its variable name
    Rule(
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\"']?\s*[:=]\s*[\"']?"
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
            r"[\"']?\s*[:=]\s*[\"']?([^\"'\s,;]{4,})[\"']?"
        ),
        group=1,
        validator=_is_real_generic_secret,
    ),
]


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


def _make_replacer(
    rule: Rule, counts: Counter, vault: Optional[SecretVault] = None
) -> Callable[[re.Match], str]:
    def _replace(match: re.Match) -> str:
        value = match.group(rule.group)
        # Skip if no value, already redacted, or rejected by the validator.
        if value is None or value.startswith("[REDACTED_"):
            return match.group(0)
        if rule.validator and not rule.validator(value):
            return match.group(0)

        counts[rule.name] += 1
        full = match.group(0)
        start = match.start(rule.group) - match.start(0)
        end = match.end(rule.group) - match.start(0)
        placeholder = (
            vault.placeholder_for(rule.name, value) if vault else f"[REDACTED_{rule.name}]"
        )
        return f"{full[:start]}{placeholder}{full[end:]}"

    return _replace


def scan_and_sanitize(code: str, vault: Optional[SecretVault] = None) -> tuple[str, Counter]:
    """Return (safe_code, counts_per_secret_type).

    Pass a SecretVault to get numbered placeholders that can be restored later."""
    counts: Counter = Counter()
    safe_code = code
    for rule in RULES:
        safe_code = rule.pattern.sub(_make_replacer(rule, counts, vault), safe_code)
    return safe_code, counts


def sanitize_code(code: str) -> tuple[str, list[str]]:
    """
    Redact secrets from `code`.

    Returns:
        safe_code       - code with secrets replaced by [REDACTED_<TYPE>]
        detected_issues - list of detected secret types (unique, in rule order)
    """
    safe_code, counts = scan_and_sanitize(code)
    detected_issues = list(counts.keys())
    if detected_issues:
        # Log only types/counts - NEVER the secret values themselves.
        logger.warning("Secrets redacted: %s", dict(counts))
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
    total_redactions: int
    is_clean: bool


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize_endpoint(req: SanitizeRequest) -> SanitizeResponse:
    safe_code, counts = scan_and_sanitize(req.code)
    if counts:
        logger.warning("Secrets redacted via API: %s", dict(counts))
    # Sanitize-only endpoint. Use POST /chat to also forward the masked text to Claude.
    return SanitizeResponse(
        safe_code=safe_code,
        detected_issues=list(counts.keys()),
        issue_counts=dict(counts),
        total_redactions=sum(counts.values()),
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
    safe_message, counts = scan_and_sanitize(message, vault)
    if counts:
        logger.warning("Secrets redacted before LLM call: %s", dict(counts))

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
        "total_redactions": sum(counts.values()),
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
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # never leak details (or secrets) from upstream errors
        logger.error("Upstream LLM call failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Upstream LLM request failed")
