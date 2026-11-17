"""
safe_workspace.py
=================
Build a *sanitized copy* of a project that is safe to open with AI agents.

    python safe_workspace.py build  <project> <safe_copy> [--dry-run]
    python safe_workspace.py guard  <project>

What `build` does:
  * .env files, private keys, credential files etc. are NOT copied at all
  * every other text file is passed through the secret redactor
  * heavy / irrelevant folders (.git, node_modules, .venv ...) are skipped
  * binary and very large files are skipped
  * a SAFE_WORKSPACE_REPORT.md (file names + secret TYPES only) is written

Give the AI agent the *safe copy*, never the original folder.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from security_proxy import issue_policy_metadata, scan_and_sanitize

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".idea", ".dart_tool", "build", "dist", ".gradle", "Pods", ".ssh", ".aws",
}

# Files that are never copied (matched case-insensitively on the file name).
BLOCKED_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", ".npmrc", ".pypirc", ".netrc",
    "credentials.json", "*.tfstate", "*.tfstate.*", "*.tfvars", "secrets.*",
    "*serviceaccount*.json", "*service-account*.json",
]
# Templates contain no real secrets, so they are copied (and still scanned).
TEMPLATE_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist"}

MAX_BYTES = 2 * 1024 * 1024  # skip text files larger than 2 MB


def is_blocked(filename: str) -> bool:
    name = filename.lower()
    if name in TEMPLATE_NAMES:
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in BLOCKED_PATTERNS)


@dataclass
class WorkspaceReport:
    copied: int = 0
    sanitized: dict[str, dict[str, int]] = field(default_factory=dict)  # file -> {type: n}
    logged: dict[str, dict[str, int]] = field(default_factory=dict)
    severities: dict[str, dict[str, str]] = field(default_factory=dict)
    blocked: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def total_redactions(self) -> int:
        return sum(sum(c.values()) for c in self.sanitized.values())


def build_safe_workspace(src: str | Path, dest: str | Path, dry_run: bool = False) -> WorkspaceReport:
    src_p, dest_p = Path(src).expanduser().resolve(), Path(dest).expanduser().resolve()
    if not src_p.is_dir():
        raise ValueError(f"Project folder not found: {src_p}")
    if dest_p == src_p or dest_p in src_p.parents:
        raise ValueError("The safe copy folder must be different from (and not above) the project folder.")

    report = WorkspaceReport()
    for root, dirs, files in os.walk(src_p):
        root_p = Path(root)
        # Prune folders in place; never descend into the output folder or symlinks.
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and (root_p / d).resolve() != dest_p
            and not (root_p / d).is_symlink()
        ]
        for name in files:
            path = root_p / name
            rel = path.relative_to(src_p).as_posix()

            if path.is_symlink():
                report.skipped.append(f"{rel} (symlink)")
                continue
            if is_blocked(name):
                report.blocked.append(rel)
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    report.skipped.append(f"{rel} (larger than 2 MB)")
                    continue
                text = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                report.skipped.append(f"{rel} (binary)")
                continue
            except OSError as exc:
                report.skipped.append(f"{rel} ({type(exc).__name__})")
                continue

            safe_text, counts = scan_and_sanitize(text)
            if counts:
                actions, severities = issue_policy_metadata(counts)
                redactions = {
                    kind: count for kind, count in counts.items() if actions[kind] == "redact"
                }
                logged = {
                    kind: count for kind, count in counts.items() if actions[kind] == "log"
                }
                if redactions:
                    report.sanitized[rel] = redactions
                if logged:
                    report.logged[rel] = logged
                report.severities[rel] = severities
            report.copied += 1
            if not dry_run:
                out = dest_p / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(safe_text.encode("utf-8"))

    if not dry_run:
        dest_p.mkdir(parents=True, exist_ok=True)
        (dest_p / "SAFE_WORKSPACE_REPORT.md").write_text(_render_report(report), encoding="utf-8")
    return report


def _render_report(report: WorkspaceReport) -> str:
    lines = [
        "# Safe Workspace Report", "",
        f"- Files copied: {report.copied}",
        f"- Files withheld (secret-bearing): {len(report.blocked)}",
        f"- Secrets redacted: {report.total_redactions}", "",
        "## Withheld files (not copied)",
    ]
    lines += [f"- `{p}`" for p in report.blocked] or ["- none"]
    lines += ["", "## Files with redactions (secret types and severity only, never values)"]
    lines += [
        f"- `{path}`: "
        + ", ".join(
            f"{kind}={count} ({report.severities[path][kind]})"
            for kind, count in counts.items()
        )
        for path, counts in report.sanitized.items()
    ] or ["- none"]
    lines += ["", "## Files with log-only findings (not redacted)"]
    lines += [
        f"- `{path}`: "
        + ", ".join(
            f"{kind}={count} ({report.severities[path][kind]})"
            for kind, count in counts.items()
        )
        for path, counts in report.logged.items()
    ] or ["- none"]
    lines += ["", "## Skipped files"]
    lines += [f"- {p}" for p in report.skipped] or ["- none"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Guard files for the ORIGINAL project (defence in depth)
# --------------------------------------------------------------------------
GUARD_PATTERNS = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "credentials.json", "secrets/"]
CLAUDE_DENY = ["Read(./.env)", "Read(./.env.*)", "Read(./**/*.pem)", "Read(./**/*.key)", "Read(./secrets/**)"]


def write_guard_files(project: str | Path) -> list[str]:
    """Create ignore/deny files that ask AI tools not to read secret files.

    Existing files are never overwritten. These are best-effort: check each
    tool's documentation for the exact format it supports.
    """
    proj = Path(project).expanduser().resolve()
    if not proj.is_dir():
        raise ValueError(f"Project folder not found: {proj}")
    messages: list[str] = []

    cursor = proj / ".cursorignore"
    if cursor.exists():
        messages.append(".cursorignore already exists - left untouched.")
    else:
        cursor.write_text("# Written by AI Code Security Proxy\n" + "\n".join(GUARD_PATTERNS) + "\n", encoding="utf-8")
        messages.append("Created .cursorignore")

    settings = proj / ".claude" / "settings.json"
    if settings.exists():
        messages.append(".claude/settings.json already exists - add these deny rules manually: " + json.dumps(CLAUDE_DENY))
    else:
        settings.parent.mkdir(exist_ok=True)
        settings.write_text(json.dumps({"permissions": {"deny": CLAUDE_DENY}}, indent=2) + "\n", encoding="utf-8")
        messages.append("Created .claude/settings.json with deny rules")
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an AI-safe copy of a project.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="create a sanitized copy")
    b.add_argument("project")
    b.add_argument("safe_copy")
    b.add_argument("--dry-run", action="store_true", help="scan only, write nothing")
    g = sub.add_parser("guard", help="create ignore/deny files in the original project")
    g.add_argument("project")
    args = parser.parse_args()

    try:
        if args.cmd == "guard":
            for msg in write_guard_files(args.project):
                print(msg)
            return 0
        rep = build_safe_workspace(args.project, args.safe_copy, dry_run=args.dry_run)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Files copied: {rep.copied} | withheld: {len(rep.blocked)} | "
        f"secrets redacted: {rep.total_redactions} | files with log-only findings: {len(rep.logged)}"
    )
    for p in rep.blocked:
        print(f"  [withheld] {p}")
    for p, c in rep.sanitized.items():
        print(f"  [redacted] {p}: {c}")
    for p, c in rep.logged.items():
        print(f"  [logged, not redacted] {p}: {c}")
    # Non-zero exit makes --dry-run usable as a pre-commit / CI check.
    return 1 if args.dry_run and (rep.blocked or rep.sanitized or rep.logged) else 0


if __name__ == "__main__":
    sys.exit(main())
