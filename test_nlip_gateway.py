from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace

import anthropic
from nlip_sdk.nlip import AllowedFormats, NLIP_Factory, NLIP_SubMessage

from nlip_gateway import SECURITY_REPORT_LABEL, NlipGatewaySession


def _run(session: NlipGatewaySession, message):
    return asyncio.run(session.correlated_execute(message))


def _report_from(response) -> str:
    report = response.find_labeled_submessage(SECURITY_REPORT_LABEL)
    assert report is not None
    assert isinstance(report.content, str)
    return report.content


def test_sanitize_masks_text_and_report_excludes_secret_values(monkeypatch):
    monkeypatch.setenv("NLIP_GATEWAY_MODE", "sanitize")
    fake_openai_key = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    fake_password = "Demo" + "Password" + "5678"
    message = NLIP_Factory.create_text(f'api_key = "{fake_openai_key}"')
    message.add_text(f'password = "{fake_password}"', language="french")

    response = _run(NlipGatewaySession(), message)
    report = _report_from(response)

    assert "[REDACTED_OPENAI_API_KEY_1]" in response.content
    assert "[REDACTED_GENERIC_SECRET_1]" in response.content
    assert "\n" in response.content
    assert fake_openai_key not in response.to_json()
    assert fake_password not in response.to_json()
    assert "OPENAI_API_KEY=1" in report
    assert "GENERIC_SECRET=1" in report
    assert fake_openai_key not in report
    assert fake_password not in report


def test_non_text_submessages_and_conversation_tokens_are_withheld(monkeypatch):
    monkeypatch.setenv("NLIP_GATEWAY_MODE", "sanitize")
    hidden_value = "Never" + "Forward" + "This123"
    message = NLIP_Factory.create_text("Visible text.")
    message.add_submessage(
        NLIP_SubMessage(
            format=AllowedFormats.structured,
            subformat="JSON",
            content={"password": hidden_value},
        )
    )
    message.add_conversation_token("fake-conversation-token")

    response = _run(NlipGatewaySession(), message)
    report = _report_from(response)

    assert response.content == "Visible text."
    assert hidden_value not in response.to_json()
    assert "fake-conversation-token" not in response.to_json()
    assert "Non-text parts withheld: 2" in report


def test_chat_sends_only_masked_text_and_restores_placeholders_locally(monkeypatch):
    monkeypatch.setenv("NLIP_GATEWAY_MODE", "chat")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-test-key")
    fake_openai_key = "sk-" + "proj-" + "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp"
    sent_messages: list[str] = []

    class FakeMessages:
        def create(self, **kwargs):
            sent_message = kwargs["messages"][0]["content"]
            sent_messages.append(sent_message)
            placeholder = re.search(r"\[REDACTED_OPENAI_API_KEY_1\]", sent_message)
            assert placeholder is not None
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text=f"Detected {placeholder.group(0)}")]
            )

    class FakeAnthropic:
        def __init__(self, api_key: str):
            assert api_key == "fake-test-key"
            self.messages = FakeMessages()

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    message = NLIP_Factory.create_text(f"Explain this key: {fake_openai_key}")

    response = _run(NlipGatewaySession(), message)
    report = _report_from(response)

    assert len(sent_messages) == 1
    assert fake_openai_key not in sent_messages[0]
    assert fake_openai_key in response.content
    assert fake_openai_key not in report
