# BoundaryGuard: NLIP Egress Security Proxy

**NDSS SafeOSE '27 Open-Source AI Security Hackathon**

**Area 03 — Security Functions at Unified Control Points**

BoundaryGuard is a pluggable security proxy for AI-agent communication. It places
secret detection and policy enforcement at the communication boundary, checking
both text entering an agent and the agent's text response before it reaches the
client. The control is outside the agent: integrating it does not require
changing the agent's internal logic.

The project implements a boundary control aligned with **ECMA-434 SCO 7.3.3
(Information Leakage)** by inspecting agent-to-client responses and applying
the configured secret-handling policy. This describes the implementation's
security objective; it is not an independent standards conformance
certification.

## Why a unified control point?

AI agents can read, transform, and repeat sensitive data. Prompt filtering alone
cannot prevent information from being exposed in a response. A proxy at the
communication boundary can apply one consistent policy to the traffic that is
routed through it, regardless of the agent's framework or internal design.

## Architecture and enforcement location

BoundaryGuard is designed as a **Type-1 / Type-3 Security Element (SE)** at the
NLIP communication boundary. The NLIP adapter is the enforcement point between
the client and the agent or model; the agent itself does not need to be
modified. The current demonstrator is implemented in Python using the NLIP
server abstractions and the existing secret-scanning engine.

```text
NLIP client
    │
    │ NLIP request
    ▼
┌──────────────────────────────────────────┐
│ BoundaryGuard / NLIP security gateway    │
│                                          │
│  Ingress: inspect, apply policy,         │
│           withhold uninspectable parts   │
│                                          │
│  Egress: inspect agent response,         │
│          apply policy before delivery    │
└───────────────────┬──────────────────────┘
                    │ sanitized request
                    ▼
            Agent / model service
                    │ response
                    └───────────────► egress scan ──► NLIP client
```

In chat mode, egress inspection runs after locally restoring placeholders, so
an agent echoing a request secret is checked just like a newly introduced
secret. If response scanning fails, the gateway returns an error instead of
forwarding the uninspected response. NLIP structured or other non-text request
parts that the gateway cannot inspect are withheld.

## Capabilities

### Per-type policy engine

Policies are loaded from JSON or YAML using `SECRET_POLICY_PATH`. Each detected
secret type can have an action, severity, and allowlist:

| Action | Behavior |
|---|---|
| `allow` | Pass unchanged and omit from findings. |
| `log` | Pass unchanged; log type, severity, and count only. |
| `redact` | Replace the detected value with a `[REDACTED_<TYPE>]` marker. |
| `reject` | Return HTTP 422 from `POST /sanitize`; other scanning flows redact and report it. |

Without a policy file, detected types default to `redact` with `medium`
severity. Allowlist entries support exact values and regular expressions
matched against the complete value. Allowlisted values pass silently. Supported
severities are `low`, `medium`, `high`, and `critical`.

Example YAML policy:

```yaml
default:
  action: redact
  severity: medium
secret_types:
  OPENAI_API_KEY:
    action: reject
    severity: critical
    allowlist:
      values: []
      patterns:
        - '^sk-test-.*'
```

The same schema is available in JSON:

```json
{
  "default": {"action": "redact", "severity": "medium"},
  "secret_types": {
    "OPENAI_API_KEY": {
      "action": "reject",
      "severity": "critical",
      "allowlist": {"values": [], "patterns": ["^sk-test-.*"]}
    }
  }
}
```

Select a policy before starting the service:

```powershell
$env:SECRET_POLICY_PATH = ".\secret-policy.yaml"
```

### Evasion-resistant scanning

In addition to the detector's provider-specific and generic patterns, scanning:

- Applies Unicode NFKC normalization and removes invisible format characters
  while preserving source locations for redaction.
- Attempts one layer of UTF-8 Base64 decoding and scans valid decoded text.
- Checks sufficiently long, high-entropy tokens for otherwise unknown secrets.
- Excludes UUIDs and plain hexadecimal hashes from entropy-only alerts.

These are heuristic defenses, not a guarantee of detecting every secret format.
Entropy-based checks can produce false positives.

### Response scanning and safe reporting

The NLIP gateway scans the final text response before constructing the message
sent to the client. A labeled `security_report` submessage distinguishes
ingress from egress findings and reports secret types, counts, actions, and
severities—not secret values. Application logs likewise record metadata only.

### Supported detector families

- OpenAI API keys
- GitHub tokens
- AWS access key IDs and secret access keys
- PostgreSQL, MongoDB, MySQL, and MariaDB connection strings
- PEM private keys
- Slack, Stripe, and Google API keys
- Bearer tokens
- Generic password, token, API-key, secret, and auth assignments
- High-entropy tokens

## Get started

Python 3.10 or later is recommended. From the repository directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On macOS or Linux, activate the environment with:

```bash
source .venv/bin/activate
```

### Run the NLIP gateway

Start the gateway on localhost:

```powershell
.\.venv\Scripts\python.exe -m uvicorn nlip_gateway:app --reload --host 127.0.0.1 --port 8001
```

The default `NLIP_GATEWAY_MODE=sanitize` mode scans and sanitizes NLIP text
without calling a model. To enable the Claude-backed demo, configure the
environment in the gateway terminal before starting it:

```powershell
$env:NLIP_GATEWAY_MODE = "chat"
$env:ANTHROPIC_API_KEY = "YOUR_ANTHROPIC_API_KEY"
```

The gateway sends masked text to Claude and restores placeholders locally
before its egress scan. The egress scan then applies the configured policy
before any response is sent back to the NLIP client.

In a second terminal, run the demo client:

```powershell
.\.venv\Scripts\python.exe nlip_demo_client.py
```

### Run the HTTP proxy or UI

Run the standalone FastAPI sanitizer:

```powershell
.\.venv\Scripts\python.exe -m uvicorn security_proxy:app --reload --port 8000
```

Interactive API documentation is available at `http://localhost:8000/docs`.
The Streamlit demonstration UI can be started with:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Evaluation and tests

### Automated test suite

The current suite has **16 passing pytest tests** covering detector
obfuscation, policy parsing and actions, API behavior, NLIP ingress/egress
handling, and evaluation-report metrics. Run the entire suite from the
repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

To run only the NLIP gateway tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q test_nlip_gateway.py
```

### Detection evaluation harness

`eval.py` compares the project detector with a basic regex baseline. Supply
three datasets: positive secret samples, benign negative samples, and evasion
samples. Files can be newline-delimited text (`.txt`), a JSON array of strings
(`.json`), or JSON Lines containing one string per line (`.jsonl`). Use JSON
when a sample spans multiple lines.

Example invocation:

```powershell
.\.venv\Scripts\python.exe eval.py `
  --positive positive.json `
  --negative negative.json `
  --evasion evasion.json `
  --iterations 100
```

The output is JSON and includes:

| Metric | Meaning |
|---|---|
| Positive recall | Fraction of positive samples detected. |
| Evasion recall | Fraction of evasion samples detected. |
| Overall recall | Recall across positive and evasion samples, weighted by sample count. |
| False-alarm rate | Fraction of negative samples detected. |
| Latency p50 / p95 | Per-sample detector latency in milliseconds. |
| Throughput | Combined samples processed per second. |

Rates use a `0.0`–`1.0` scale. `--iterations` controls timing repetitions;
detection metrics are calculated once per sample. The harness warms up on the
samples before timing and reports detector runtime only—it does not measure
network or model latency.

Use synthetic credentials in evaluation datasets. No benchmark scores are
published here because measured rates and timings depend on the supplied
dataset, environment, and machine. The harness is intended to make comparisons
repeatable against realistic positive, negative, and evasion corpora.

## Other integrations

- **Sanitize API:** `POST /sanitize` returns sanitized text and findings.
- **Safe Chat API:** `POST /chat` sanitizes prompts and code before forwarding
  masked text to Claude, with optional local placeholder restoration.
- **Safe Workspace:** `safe_workspace.py build` creates a sanitized project
  copy; credential files are withheld, text files are scanned, and a report
  records secret types without values. The `guard` command can add best-effort
  ignore/deny files.
- **Library use:** `scan_and_sanitize()` returns sanitized text and per-type
  counts; `sanitize_code()` offers a simpler convenience API.

## Security boundaries and limitations

- The proxy protects traffic only when clients and agents are routed through
  it; it cannot protect bypass paths.
- The NLIP gateway scans text. Uninspectable non-text request parts are
  withheld rather than forwarded.
- Base64 scanning is limited to one layer of valid UTF-8 text. Detection rules
  and entropy thresholds may miss uncommon formats or flag benign values.
- `allow` and `log` intentionally leave matching values unchanged. Review
  allowlists and policy files carefully.
- `eval.py` provides a local benchmark harness, not a security certification or
  proof of complete detection.

## Repository layout

```text
security_proxy.py                 Detection engine, policy enforcement, HTTP API
secret_policy.py                  JSON/YAML policy loading and validation
nlip_gateway.py                   NLIP boundary gateway with ingress/egress scans
nlip_demo_client.py               Example NLIP client
safe_workspace.py                 Sanitized project-copy and guard utilities
app.py                            Streamlit demonstration UI
eval.py                           Detector-versus-baseline evaluation CLI
test_nlip_gateway.py              NLIP gateway tests
test_secret_detection_obfuscation.py  Evasion-resistance tests
test_secret_policy.py             Policy behavior tests
test_eval.py                      Evaluation harness tests
requirements.txt                  Runtime and test dependencies
```

## Hackathon alignment

Area 03 emphasizes security functions at unified control points. BoundaryGuard
centralizes inspection and policy at the NLIP communication boundary, applies
consistent ingress and egress handling without changing agent internals, and
supports measurable evaluation of detection quality and runtime cost. Its
egress scan is specifically intended to mitigate information leakage in
agent-to-client responses, in alignment with ECMA-434 SCO 7.3.3.

Project disclosures: [ETHICS.md](ETHICS.md) and [SECURITY.md](SECURITY.md).
