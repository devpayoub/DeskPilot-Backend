"""Provider-agnostic chat completion with JSON output and explicit usage.

Differences from a naive wrapper, each learned the hard way:

* **Usage is returned, not just logged.** The agent's cost per run is a headline
  metric, so the caller needs the token counts in hand.
* **The ``reasoning`` body field is conditional.** IteraCompute needs
  ``{"reasoning": false}``; Groq and OpenAI reject unknown body fields.
* **No hidden retries.** The agent loop owns its own retry budget, so a client
  that silently retried four times would blow through it.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

from django.conf import settings
from openai import OpenAI

logger = logging.getLogger(__name__)


class ChatNotConfigured(Exception):
    """No API key configured; the run cannot proceed."""


class ChatResponseError(Exception):
    """The provider returned something unusable (empty or non-JSON)."""


class ChatProviderError(Exception):
    """The provider refused the request outright: auth, billing, unknown model.

    Retrying these is pointless — the same request will be refused again — and
    reporting them as an agent budget failure actively misleads: it sends you
    looking for a loop bug when the real problem is an unpaid account.
    """


_REFUSAL_STATUSES = frozenset({401, 402, 403, 404})


def _provider_refusal(exc: Exception) -> str | None:
    """The provider's own message when it refused outright, else None."""
    status = getattr(exc, "status_code", None)
    if status not in _REFUSAL_STATUSES:
        return None

    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
    return str(exc) or f"provider returned HTTP {status}"


def _rejects_json_mode(exc: Exception) -> bool:
    """True when the failure looks like 'this provider does not support json_object'."""
    text = str(exc).lower()
    markers = (
        "response_format",
        "json_object",
        "json mode",
        "unsupported parameter",
        "unrecognized request argument",
    )
    return any(marker in text for marker in markers)


@dataclass(frozen=True)
class ChatUsage:
    model: str
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def get_client(timeout: float | None = None, max_retries: int | None = None) -> OpenAI:
    api_key = (getattr(settings, "LLM_API_KEY", "") or "").strip()
    if not api_key:
        raise ChatNotConfigured(
            "LLM_API_KEY is not set. Add it to .env and recreate the worker."
        )
    return OpenAI(
        api_key=api_key,
        base_url=settings.LLM_BASE_URL,
        timeout=float(timeout if timeout is not None else os.getenv("LLM_TIMEOUT", "60")),
        max_retries=int(max_retries if max_retries is not None else 0),
    )


def chat_json(
    system_prompt: str,
    user_prompt: str,
    *,
    timeout: float | None = None,
    max_retries: int | None = None,
    max_tokens: int | None = None,
) -> tuple[dict, ChatUsage]:
    """Return ``(payload, usage)`` for a single JSON-mode completion."""
    client = get_client(timeout=timeout, max_retries=max_retries)
    model = settings.LLM_MODEL

    request: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens or int(os.getenv("LLM_MAX_TOKENS", "1024")),
        "response_format": {"type": "json_object"},
        "temperature": 0,
    }
    if getattr(settings, "LLM_SEND_REASONING_PARAM", False):
        request["extra_body"] = {"reasoning": False}

    try:
        completion = client.chat.completions.create(**request)
    except Exception as exc:
        refusal = _provider_refusal(exc)
        if refusal is not None:
            raise ChatProviderError(refusal) from exc

        # Many OpenAI-compatible proxies reject `response_format: json_object`.
        # The prompt already demands JSON and the parser strips code fences, so the
        # only thing lost is the provider-side guarantee — retry once without it
        # rather than failing a run over a vendor quirk.
        if not _rejects_json_mode(exc):
            raise
        logger.warning("provider rejected response_format; retrying without JSON mode")
        request.pop("response_format", None)
        completion = client.chat.completions.create(**request)

    usage_obj = getattr(completion, "usage", None)
    usage = ChatUsage(
        model=getattr(completion, "model", model),
        prompt_tokens=int(getattr(usage_obj, "prompt_tokens", 0) or 0),
        completion_tokens=int(getattr(usage_obj, "completion_tokens", 0) or 0),
    )

    raw = (completion.choices[0].message.content or "").strip()
    if not raw:
        raise ChatResponseError("Chat model returned empty content.")
    if raw.startswith("```"):
        raw = raw.strip("`")
        start, end = raw.find("{"), raw.rfind("}")
        if start != -1 and end != -1:
            raw = raw[start : end + 1]

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ChatResponseError(f"Chat model returned non-JSON: {raw[:200]}") from exc

    if not isinstance(payload, dict):
        raise ChatResponseError("Chat model returned a non-object JSON payload.")

    logger.info(
        "llm call model=%s prompt_tokens=%d completion_tokens=%d",
        usage.model,
        usage.prompt_tokens,
        usage.completion_tokens,
    )
    return payload, usage
