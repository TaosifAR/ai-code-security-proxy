"""NLIP security gateway built on the installed NLIP server abstractions."""

from __future__ import annotations

import asyncio
import logging
import os
from collections import Counter

from nlip_sdk.nlip import (
    AllowedFormats,
    NLIP_Factory,
    NLIP_Message,
    nlip_compare_string,
)
from nlip_server.server import NLIP_Session, SafeApplication, setup_server

from security_proxy import SecretVault, safe_chat, scan_and_sanitize

logger = logging.getLogger("nlip_gateway")

SECURITY_REPORT_LABEL = "security_report"
TEXT_LANGUAGE = "english"


def _is_scannable_text(format_name: str, content: object) -> bool:
    return nlip_compare_string(format_name, AllowedFormats.text) and isinstance(content, str)


def _extract_text_and_withheld(message: NLIP_Message) -> tuple[str, int]:
    text_parts: list[str] = []
    withheld_parts = 0

    if _is_scannable_text(message.format, message.content):
        text_parts.append(message.content)
    else:
        withheld_parts += 1

    for submessage in message.submessages or []:
        if _is_scannable_text(submessage.format, submessage.content):
            text_parts.append(submessage.content)
        else:
            withheld_parts += 1

    return "\n".join(text_parts), withheld_parts


def _security_report(counts: Counter[str], withheld_parts: int) -> str:
    secret_counts = ", ".join(f"{kind}={count}" for kind, count in counts.items()) or "none"
    return (
        f"Secret types and counts: {secret_counts}. "
        f"Non-text parts withheld: {withheld_parts}."
    )


def _error_response(code: str, report: str | None = None) -> NLIP_Message:
    response = NLIP_Factory.create_error_code(code)
    if report is not None:
        response.add_text(report, language=TEXT_LANGUAGE, label=SECURITY_REPORT_LABEL)
    return response


class NlipGatewaySession(NLIP_Session):
    async def execute(self, msg: NLIP_Message) -> NLIP_Message:
        try:
            text, withheld_parts = _extract_text_and_withheld(msg)
            vault = SecretVault()
            masked_text, counts = scan_and_sanitize(text, vault)
            report = _security_report(counts, withheld_parts)
            logger.info(
                "NLIP request processed: secret_types=%s non_text_parts_withheld=%d",
                dict(counts),
                withheld_parts,
            )
        except Exception as exc:
            logger.error("NLIP request processing failed (%s)", type(exc).__name__)
            return _error_response("NLIP_GATEWAY_PROCESSING_ERROR")

        mode = os.getenv("NLIP_GATEWAY_MODE", "sanitize").strip().lower()
        if mode not in {"sanitize", "chat"}:
            logger.error("NLIP gateway mode is invalid")
            return _error_response("NLIP_GATEWAY_INVALID_MODE", report)

        if mode == "chat" and masked_text:
            try:
                chat_result = await asyncio.to_thread(
                    safe_chat,
                    masked_text,
                    restore=False,
                )
                answer = chat_result["reply"]
                if not isinstance(answer, str):
                    raise TypeError("safe_chat returned a non-text reply")
                response_text = vault.restore(answer)
            except Exception as exc:
                logger.error("NLIP chat request failed (%s)", type(exc).__name__)
                return _error_response("NLIP_GATEWAY_CHAT_ERROR", report)
        else:
            response_text = masked_text

        response = NLIP_Factory.create_text(response_text, language=TEXT_LANGUAGE)
        response.add_text(report, language=TEXT_LANGUAGE, label=SECURITY_REPORT_LABEL)
        return response

    async def correlated_execute(self, msg: NLIP_Message) -> NLIP_Message:
        # The base method copies conversation tokens into the response; this gateway withholds them.
        return await self.execute(msg)


class NlipGatewayApplication(SafeApplication):
    def create_session(self) -> NLIP_Session:
        return NlipGatewaySession()


app = setup_server(NlipGatewayApplication())
