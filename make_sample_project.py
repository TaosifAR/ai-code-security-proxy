"""
make_sample_project.py
======================
Creates a small throwaway project full of FAKE secrets, for demoing the
Safe Workspace feature.

    python make_sample_project.py [output_folder]      (default: sample-project)

Fake secrets are assembled at runtime, so this script itself contains no
secret-looking literals and will not trip GitHub push protection.
"""

import sys
from pathlib import Path

# All values below are fake and for demonstration only.
OPENAI = "sk-" + "proj-" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"
AWS_ID = "AKIA" + "Z7XQ2WERTY45ABCD"
AWS_SECRET = "kJ8sD2fG5hL9qW3eR6tY" + "1uI4oP7aS0dF3gH6jK9l"
DB_URL = "postgresql://" + "admin:S3cretPass@db.example.com:5432/shop"

FILES = {
    ".env": (
        f"OPENAI_API_KEY={OPENAI}\n"
        f"DATABASE_URL={DB_URL}\n"
        "JWT_SECRET=fake-jwt-secret-for-demo-only\n"
    ),
    ".env.example": "OPENAI_API_KEY=\nDATABASE_URL=\nJWT_SECRET=\n",
    "server.pem": "FAKE PRIVATE KEY FILE (demo only)\n",
    "main.py": (
        "import openai\n\n"
        f'openai.api_key = "{OPENAI}"\n\n'
        "def ask(question: str) -> str:\n"
        "    return openai.ChatCompletion.create(messages=[{'role': 'user', 'content': question}])\n"
    ),
    "config/settings.py": (
        f'DATABASE_URL = "{DB_URL}"\n'
        'ADMIN_PASSWORD = "Admin@2026!"\n'
        "DEBUG = True\n"
    ),
    "utils/storage.py": (
        "import boto3\n\n"
        f'aws_access_key_id = "{AWS_ID}"\n'
        f'aws_secret_access_key = "{AWS_SECRET}"\n'
        's3 = boto3.client("s3")\n'
    ),
    "README.md": "# Sample project\n\nA tiny demo project. Nothing sensitive here.\n",
    "node_modules/lib/index.js": "console.log('dependency code, always skipped');\n",
}


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample-project").resolve()
    for rel, content in FILES.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    # A small binary file (PNG header bytes), which the workspace builder skips.
    (out / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe\x00\x00")

    print(f"Sample project created at: {out}")
    print("Next: open the 'Safe Workspace' tab and use")
    print(f"  Project folder : {out}")
    print(f"  Safe copy folder: {out}-safe")


if __name__ == "__main__":
    main()
