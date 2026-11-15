"""Send a fake-secret NLIP message to the local security gateway."""

from __future__ import annotations

import os

import httpx
from nlip_sdk.nlip import NLIP_Factory, NLIP_Message


def main() -> None:
    base_url = os.getenv("NLIP_GATEWAY_URL", "http://127.0.0.1:8001/nlip/")
    fake_openai_key = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    fake_github_token = "gh" + "p_" + ("a" * 36)
    fake_password = "Demo" + "Password" + "1234"

    message = NLIP_Factory.create_text(
        f'Please review this config: api_key = "{fake_openai_key}"'
    )
    message.add_text(f'password = "{fake_password}"')
    message.add_text(f"GitHub token: {fake_github_token}")

    response = httpx.post(
        base_url,
        json=message.to_dict(),
        timeout=30.0,
        follow_redirects=True,
    )
    response.raise_for_status()
    gateway_response = NLIP_Message.model_validate(response.json())
    print(gateway_response.to_json())


if __name__ == "__main__":
    main()
