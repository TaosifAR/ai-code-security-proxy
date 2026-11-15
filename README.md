# 🛡️ AI Code Security Proxy & Guardrail

A pluggable Python security middleware that sits between developers and AI coding assistants.
It intercepts code, **detects secrets with regex, redacts them** as `[REDACTED_<TYPE>]`,
logs a warning (never the secret itself), and only then lets the sanitized code through to the LLM / agent.

> Built for the **NDSS SafeOSE '27 Open-Source AI Security Hackathon**, Focus Area 03.

## The problem

Developers routinely paste code into LLM chats or hand files to AI agents for debugging.
Along the way they leak API keys, database credentials, AWS tokens and private keys to a third party.

## The solution

```
Developer / IDE / Agent ──►  POST /sanitize  ──►  Sanitized code ──►  LLM / AI agent
                           (Security Proxy)
                      detect → redact → log warning
```

## Alignment with Focus Area 03: Security Functions at Unified Control Points

Instead of trusting every developer, tool and agent to handle secrets correctly, this project puts
**one enforcement point** in front of all AI traffic:

| Principle | How this project applies it |
|---|---|
| **Single choke point** | Every request goes through `POST /sanitize`; no path to the LLM bypasses it. |
| **Centralized policy** | All detection rules live in one list (`RULES` in `security_proxy.py`). Add a rule once, every client is protected. |
| **Tool-agnostic** | Plain HTTP + JSON: works with chat UIs, IDE plugins, CI jobs and autonomous agents. |
| **Safe auditing** | Logs secret *types and counts only*, never values. |
| **Open source & pluggable** | Small, dependency-light, importable as a library (`sanitize_code`) or run as a service. |

## Detected secrets

- OpenAI API keys (`sk-...`, `sk-proj-...`)
- GitHub tokens (`ghp_...`, `gho_...`, `github_pat_...`)
- AWS Access Key IDs (`AKIA...`) and Secret Access Keys
- Database URLs: PostgreSQL, MongoDB, MySQL / MariaDB
- PEM private keys
- Generic `api_key`, `password`, `secret`, `token` assignments (env lookups like `os.getenv(...)` are ignored)

## Setup

```bash
# 1. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
```

## Run

**Streamlit demo UI** (runs the sanitizer in-process):

```bash
streamlit run app.py
```

**FastAPI security proxy:**

```bash
uvicorn security_proxy:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs. To make the UI call the API, enable *Use FastAPI endpoint* in the sidebar.

**Example request:**

```bash
curl -X POST http://localhost:8000/sanitize \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"hunter2hunter2\""}'
```

```json
{
  "safe_code": "password = \"[REDACTED_GENERIC_SECRET]\"",
  "detected_issues": ["GENERIC_SECRET"],
  "issue_counts": {"GENERIC_SECRET": 1},
  "total_redactions": 1,
  "is_clean": false
}
```

**Use as a library:**

```python
from security_proxy import sanitize_code

safe_code, issues = sanitize_code(my_code)
```

## Three ways to use it

### 1. Scanner (`POST /sanitize`)
Paste code, get masked code back. Placeholders look like `[REDACTED_OPENAI_API_KEY]`.

### 2. Safe Chat / Proxy mode (`POST /chat`)
The proxy masks secrets, sends **only the masked text** to Claude, and (optionally) puts the original values
back into the answer *locally*, so the developer's code still works. Secrets never leave the machine.

```bash
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "your-key"
uvicorn security_proxy:app --reload --port 8000
```

```bash
curl -X POST http://localhost:8000/chat -H "Content-Type: application/json" \
  -d '{"prompt": "Why does this fail?", "code": "password = \"hunter2hunter2\"", "restore": true}'
```

The model defaults to `claude-sonnet-5-5`; override with the `CLAUDE_MODEL` environment variable.
The response includes `sanitized_message`, i.e. exactly what the LLM saw, which is handy for auditing.

### 3. Safe Workspace (protect the whole project folder)
AI agents and editor extensions can read everything in an open workspace, including `.env`. Instead of
trusting every tool's settings, build a sanitized copy and open **that** with AI tools:

```bash
python safe_workspace.py build  C:\path\to\my-project  C:\path\to\my-project-safe --dry-run   # preview
python safe_workspace.py build  C:\path\to\my-project  C:\path\to\my-project-safe             # create
python safe_workspace.py guard  C:\path\to\my-project      # add .cursorignore / .claude deny rules
```

- `.env`, `.env.*`, `*.pem`, `*.key`, credential files etc. are **never copied** (`.env.example` is kept)
- every other text file is redacted; `.git`, `node_modules`, `.venv`, binaries and files over 2 MB are skipped
- a `SAFE_WORKSPACE_REPORT.md` lists withheld files and secret *types* (never values)
- `--dry-run` exits with code 1 if anything sensitive is found, so it also works as a CI / pre-commit check
- `guard` writes best-effort ignore/deny files for the original project. Check each tool's docs for the exact
  format it honours (for example GitHub Copilot content exclusion is configured in GitHub settings, not in a file).

## NLIP Integration

The NLIP gateway is a security control point inside NLIP agent communication. It receives an NLIP message,
scans its text with the existing secret rules, and withholds non-text content it cannot inspect. It returns a
labeled `security_report` submessage containing secret types and counts only.

Install the requirements, then start the gateway from the project directory:

```powershell
.\.venv\Scripts\python.exe -m uvicorn nlip_gateway:app --reload --host 127.0.0.1 --port 8001
```

In another terminal, send the demo message containing runtime-assembled fake secrets:

```powershell
.\.venv\Scripts\python.exe nlip_demo_client.py
```

The gateway defaults to `NLIP_GATEWAY_MODE=sanitize`, which returns masked text without an API key. To use
chat mode in PowerShell, set the mode and API key in the gateway terminal before starting it:

```powershell
$env:NLIP_GATEWAY_MODE = "chat"
$env:ANTHROPIC_API_KEY = "YOUR_ANTHROPIC_API_KEY"
```

The gateway sends only masked text to Claude and restores placeholders in the reply locally.

Run the gateway tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest -q test_nlip_gateway.py
```

The `nlip-client` project is not available as an installable package from the configured Python package index.
Its upstream Git source also refers to a sibling `../nlip_sdk` checkout, so it cannot be installed by itself.
The demo therefore uses the installed NLIP SDK message model and HTTPX to post to the `/nlip/` route defined by
`nlip-server`.

## Project structure

```
├── security_proxy.py   # detection rules, sanitize_code(), /sanitize, /chat (proxy mode)
├── safe_workspace.py   # sanitized project copy + guard files (CLI and library)
├── app.py              # Streamlit demo UI (Scanner / Safe Chat / Safe Workspace tabs)
├── nlip_gateway.py      # NLIP server that sanitizes messages or proxies masked text to Claude
├── nlip_demo_client.py  # sends an NLIP message with fake secrets to the gateway
├── test_nlip_gateway.py
├── requirements.txt
└── README.md
```

## Limitations & future work

- Regex detection can miss unusual formats and may flag some false positives; entropy-based detection would complement it.
- Add per-organization custom rules and an allow-list.
- A proxy only protects traffic that goes through it: tools must be pointed at it, or fed the safe workspace copy.
- Add request audit logs and support for more LLM providers.
- Support file/diff scanning and a pre-commit hook.

## Note on sample secrets

All sample keys in the demo are fake and assembled at runtime so GitHub push protection does not block your commits.
