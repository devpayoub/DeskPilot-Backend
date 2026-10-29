"""Check the configured LLM endpoint end to end.

Third-party OpenAI-compatible providers fail in specific, distinguishable ways:
a missing key, a key that is rejected, a model name that does not exist on that
provider, a proxy that blocks the request, or a response that is not JSON. This
command tells you which one you have instead of leaving a stack trace.

    python manage.py check_llm
"""
from __future__ import annotations

import time

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.llm.chat_client import (
    ChatNotConfigured,
    ChatResponseError,
    chat_json,
    get_client,
)

PROBE_SYSTEM = "You reply with JSON only."
PROBE_USER = 'Reply with exactly {"ok": true} and nothing else.'


class Command(BaseCommand):
    help = "Verify that the configured LLM provider, key and model actually work."

    def handle(self, *args, **options):
        key = (getattr(settings, "LLM_API_KEY", "") or "").strip()
        base_url = settings.LLM_BASE_URL
        model = settings.LLM_MODEL

        self.stdout.write("Configuration")
        self.stdout.write(f"  base URL   {base_url}")
        self.stdout.write(f"  model      {model}")
        # Last four characters only. Enough to tell two keys apart while debugging,
        # not enough to help anyone who reads the terminal scrollback or a pasted log.
        self.stdout.write(f"  api key    {'set (…' + key[-4:] + ')' if key else 'MISSING'}")
        self.stdout.write(f"  json mode  response_format=json_object")
        self.stdout.write("")

        if not key:
            self.stderr.write(
                self.style.ERROR(
                    "No API key. Add LLM_API_KEY to .env at the repo root, then restart "
                    "the API process."
                )
            )
            return

        started = time.monotonic()
        try:
            payload, usage = chat_json(PROBE_SYSTEM, PROBE_USER, timeout=30, max_retries=0)
        except ChatNotConfigured as exc:
            self.stderr.write(self.style.ERROR(f"Not configured: {exc}"))
            return
        except ChatResponseError as exc:
            self.stderr.write(self.style.ERROR(f"Provider returned unusable output: {exc}"))
            self._hint(str(exc))
            return
        except Exception as exc:
            self.stderr.write(self.style.ERROR(f"{type(exc).__name__}: {exc}"))
            self._hint(str(exc))
            return

        elapsed = (time.monotonic() - started) * 1000
        self.stdout.write(self.style.SUCCESS("Provider responded."))
        self.stdout.write(f"  latency     {elapsed:.0f} ms")
        self.stdout.write(f"  model used  {usage.model}")
        self.stdout.write(f"  tokens      {usage.prompt_tokens} in / {usage.completion_tokens} out")
        self.stdout.write(f"  parsed JSON {payload}")

        if usage.model and usage.model != model:
            self.stdout.write(
                self.style.WARNING(
                    f"  note: the provider answered as '{usage.model}', not '{model}'. "
                    "Price rows key off the model that answered, so add a ModelPrice "
                    "for it."
                )
            )

        # The thing the agent depends on is that a JSON object comes back, not that
        # the text looks nice. Say so explicitly.
        if not isinstance(payload, dict):
            self.stderr.write(self.style.ERROR("  the response was not a JSON object"))
            return

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("This model can drive the agent. Next:")
        )
        self.stdout.write("  python manage.py run_evals --mode live --limit 5")
        self.stdout.write("  then open the console and press 'Run agent' on a ticket.")

    def _hint(self, message: str) -> None:
        lowered = message.lower()
        self.stdout.write("")
        if "invalid api key" in lowered or "401" in lowered or "unauthorized" in lowered:
            self.stdout.write("  → the key was rejected. Check it was copied whole and is active.")
        elif "model" in lowered and ("not found" in lowered or "does not exist" in lowered):
            self.stdout.write(
                f"  → the provider does not offer '{settings.LLM_MODEL}'. "
                "List the models it does offer and update LLM_MODEL."
            )
        elif "502" in lowered or "connection" in lowered or "timeout" in lowered:
            self.stdout.write(
                "  → the endpoint did not answer. Check the base URL and that the host "
                "is reachable from this machine."
            )
        elif "json" in lowered:
            self.stdout.write(
                "  → the provider answered, but not with a JSON object. The agent needs "
                "JSON; try a different model."
            )
