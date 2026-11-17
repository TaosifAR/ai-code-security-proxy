"""
app.py - Streamlit demo UI for the AI Code Security Proxy.

Run:  streamlit run app.py
"""

import requests
import streamlit as st

from safe_workspace import build_safe_workspace, write_guard_files
from security_proxy import issue_policy_metadata, safe_chat, scan_and_sanitize
from secret_policy import PolicyConfigurationError

st.set_page_config(page_title="AI Code Security Proxy", page_icon="🛡️", layout="wide")

# --------------------------------------------------------------------------
# Sample inputs. Fake secrets are assembled at runtime so that GitHub's
# secret-scanning push protection doesn't block your commit.
# --------------------------------------------------------------------------
_OPENAI = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
_GITHUB = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"

SAMPLES = {
    "🔑 OpenAI Key": f'import openai\n\nclient = openai.OpenAI(api_key="{_OPENAI}")\nprint(client.models.list())\n',
    "🐙 GitHub Token": f'import requests\n\nTOKEN = "{_GITHUB}"\nr = requests.get("https://api.github.com/user", headers={{"Authorization": f"token {{TOKEN}}"}})\n',
    "☁️ AWS Credentials": f'import boto3\n\naws_access_key_id = "{_AWS_ID}"\naws_secret_access_key = "{_AWS_SECRET}"\ns3 = boto3.client("s3")\n',
    "🗄️ DB Connection": 'DATABASE_URL = "postgresql://admin:Sup3rS3cret@db.example.com:5432/prod"\nMONGO_URI = "mongodb+srv://root:hunter2@cluster0.example.mongodb.net/app"\n',
    "🧪 Mixed Leak": f'config = {{\n    "api_key": "{_OPENAI}",\n    "password": "P@ssw0rd123!",\n    "db": "mysql://root:toor@localhost:3306/shop",\n}}\n',
    "✅ Clean Code": 'import os\n\ndef greet(name: str) -> str:\n    api_key = os.getenv("API_KEY")\n    return f"Hello, {name}!"\n',
}

if "code_input" not in st.session_state:
    st.session_state.code_input = SAMPLES["🧪 Mixed Leak"]


def _load_sample(name: str) -> None:
    st.session_state.code_input = SAMPLES[name]


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Settings")
    use_api = st.toggle("Use FastAPI endpoint", value=False,
                        help="Off: run the sanitizer in-process. On: call POST /sanitize.")
    api_url = st.text_input("API URL", "http://localhost:8000/sanitize", disabled=not use_api)
    api_key = st.text_input("Anthropic API key (for Safe Chat)", type="password",
                            help="Or set the ANTHROPIC_API_KEY environment variable. Kept in memory only.")
    st.divider()
    st.caption("Detects: OpenAI keys, GitHub tokens, AWS keys, DB URLs, private keys, "
               "and generic api_key / password / secret / token assignments.")


def run_sanitizer(code: str):
    """Return sanitized text, counts, actions, and severities."""
    if use_api:
        resp = requests.post(api_url, json={"code": code}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return (
            data["safe_code"],
            data["issue_counts"],
            data["issue_actions"],
            data["issue_severities"],
        )
    safe, counts = scan_and_sanitize(code)
    count_dict = dict(counts)
    actions, severities = issue_policy_metadata(counts)
    return safe, count_dict, actions, severities


# --------------------------------------------------------------------------
# Main UI
# --------------------------------------------------------------------------
st.title("🛡️ AI Code Security Proxy")
st.caption("Redact secrets *before* your code reaches an LLM or AI agent.")

tab_scan, tab_chat, tab_ws = st.tabs(["🔍 Scanner", "💬 Safe Chat (Proxy)", "📁 Safe Workspace"])

with tab_scan:
    st.subheader("Try a sample")
    cols = st.columns(len(SAMPLES))
    for col, name in zip(cols, SAMPLES):
        col.button(name, on_click=_load_sample, args=(name,), use_container_width=True)

    st.text_area("Paste code here", key="code_input", height=240)

    if st.button("🔍 Scan & Sanitize", type="primary"):
        code = st.session_state.code_input
        if not code.strip():
            st.info("Please enter some code first.")
        else:
            try:
                safe_code, counts, actions, severities = run_sanitizer(code)
            except PolicyConfigurationError as exc:
                st.error(f"Secret policy configuration error: {exc}")
                st.stop()
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 422:
                    st.error("The request was rejected by the secret handling policy.")
                else:
                    st.error(f"Scanner API returned HTTP {exc.response.status_code if exc.response else 'error'}.")
                st.stop()
            except requests.RequestException as exc:
                st.error(f"Could not reach the API: {exc}")
                st.stop()

            redactions = sum(
                count for secret_type, count in counts.items()
                if actions[secret_type] == "redact"
            )
            if redactions:
                st.warning(f"⚠️ {redactions} secret(s) redacted "
                           f"across {len(counts)} type(s).")
            if any(action == "log" for action in actions.values()):
                st.info("Some findings were logged by policy and left unchanged.")
            if counts:
                m1, m2 = st.columns(2)
                m1.metric("Total redactions", redactions)
                m2.metric("Secret types", len(counts))
                st.table(
                    {
                        "Secret type": list(counts),
                        "Count": list(counts.values()),
                        "Action": [actions[kind] for kind in counts],
                        "Severity": [severities[kind] for kind in counts],
                    }
                )
            else:
                st.success("✅ No secrets detected. Code is clean.")

            left, right = st.columns(2)
            with left:
                st.markdown("#### 🔴 Original Code")
                st.code(code, language="python")
            with right:
                st.markdown("#### 🟢 Sanitized Safe Code")
                st.code(safe_code, language="python")


# --------------------------------------------------------------------------
# Tab 2: Proxy mode - mask, forward to Claude, restore locally
# --------------------------------------------------------------------------
with tab_chat:
    st.caption("Your code is masked first; Claude only ever sees the masked version.")
    chat_prompt = st.text_input("Your question", value="Why does this code fail?", key="chat_prompt")
    chat_code = st.text_area("Code (may contain secrets)", value=SAMPLES["🧪 Mixed Leak"],
                             height=200, key="chat_code")
    restore = st.checkbox("Restore original values in the answer (done locally)", value=True)

    if st.button("🚀 Send via proxy", type="primary"):
        result, error = None, None
        try:
            with st.spinner("Masking and contacting Claude..."):
                if use_api:
                    chat_url = api_url.rsplit("/", 1)[0] + "/chat"
                    resp = requests.post(chat_url, json={"prompt": chat_prompt, "code": chat_code,
                                                         "restore": restore}, timeout=120)
                    resp.raise_for_status()
                    result = resp.json()
                else:
                    result = safe_chat(chat_prompt, chat_code, restore, api_key=api_key or None)
        except PolicyConfigurationError as exc:
            error = f"Secret policy configuration error: {exc}"
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 422:
                error = "The request was rejected by the secret handling policy."
            else:
                error = f"Request failed (HTTP {exc.response.status_code if exc.response else 'error'})."
        except RuntimeError as exc:
            error = str(exc)
        except Exception as exc:  # network / upstream errors
            error = f"Request failed ({type(exc).__name__})."

        if error:
            st.error(error)
        elif result:
            if result["total_redactions"]:
                st.warning(f"⚠️ {result['total_redactions']} secret(s) masked before reaching Claude.")
            elif result["detected_issues"]:
                st.info("Findings were allowed or logged by policy and left unchanged.")
            else:
                st.success("✅ No secrets found in the message.")
            if result["detected_issues"]:
                st.table(
                    {
                        "Secret type": result["detected_issues"],
                        "Count": [result["issue_counts"][kind] for kind in result["detected_issues"]],
                        "Action": [result["issue_actions"][kind] for kind in result["detected_issues"]],
                        "Severity": [result["issue_severities"][kind] for kind in result["detected_issues"]],
                    }
                )
            a, b = st.columns(2)
            with a:
                st.markdown("#### 🛡️ What Claude actually saw")
                st.code(result["sanitized_message"], language="markdown")
            with b:
                st.markdown("#### 🤖 Claude's answer")
                st.markdown(result["reply"])

# --------------------------------------------------------------------------
# Tab 3: Safe workspace - sanitized project copy for AI agents
# --------------------------------------------------------------------------
with tab_ws:
    st.caption("Builds a copy of your project without .env / key files and handles detected "
               "secrets according to policy. "
               "Open the **copy** (not the original) in VS Code with AI agents.")
    ws_src = st.text_input("Project folder (original)", key="ws_src", placeholder=r"C:\Users\you\my-project")
    ws_dest = st.text_input("Safe copy folder (give THIS to AI tools)", key="ws_dest",
                            placeholder=r"C:\Users\you\my-project-safe")
    ws_dry = st.checkbox("Dry run (scan only, write nothing)", value=True)

    c1, c2 = st.columns(2)
    if c1.button("🧱 Build safe workspace", type="primary"):
        try:
            rep = build_safe_workspace(ws_src, ws_dest, dry_run=ws_dry)
        except (ValueError, OSError) as exc:
            st.error(str(exc))
        else:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Files copied", rep.copied)
            m2.metric("Files withheld", len(rep.blocked))
            m3.metric("Secrets redacted", rep.total_redactions)
            m4.metric("Log-only findings", sum(sum(c.values()) for c in rep.logged.values()))
            if rep.blocked:
                st.warning("Withheld (never copied): " + ", ".join(f"`{p}`" for p in rep.blocked))
            if rep.sanitized:
                st.table({"File": list(rep.sanitized),
                          "Redactions": [", ".join(f"{k} x{v}" for k, v in c.items())
                                         for c in rep.sanitized.values()]})
            if rep.logged:
                st.table({"File": list(rep.logged),
                          "Log-only findings": [", ".join(f"{k} x{v}" for k, v in c.items())
                                                for c in rep.logged.values()]})
            if not rep.blocked and not rep.sanitized and not rep.logged:
                st.success("✅ Nothing sensitive found.")
            if ws_dry:
                st.info("Dry run: nothing was written. Untick it to create the safe copy.")
            else:
                st.success("Safe copy created. See SAFE_WORKSPACE_REPORT.md inside it.")

    if c2.button("🚧 Add AI ignore files to original project"):
        try:
            for msg in write_guard_files(ws_src):
                st.write("•", msg)
            st.caption("Best-effort: verify the format in each tool's docs.")
        except (ValueError, OSError) as exc:
            st.error(str(exc))
