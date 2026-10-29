"""Seed a price row for the configured model.

Prices are public but they change. The values below were correct when written;
**verify them against your provider's pricing page before quoting a cost figure**,
and update the row rather than the code.
"""
from __future__ import annotations

from decimal import Decimal

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.llm.models import ModelPrice

# model -> (input USD per 1M tokens, output USD per 1M tokens, note)
KNOWN_PRICES = {
    "llama-3.3-70b-versatile": (
        Decimal("0.59"),
        Decimal("0.79"),
        "Groq published price; verify before quoting.",
    ),
}


class Command(BaseCommand):
    help = "Create a ModelPrice row for the configured LLM model."

    def add_arguments(self, parser):
        parser.add_argument(
            "--model",
            default=None,
            help="Model identifier. Defaults to settings.LLM_MODEL.",
        )
        parser.add_argument("--input", type=Decimal, default=None, help="USD per 1M input tokens.")
        parser.add_argument("--output", type=Decimal, default=None, help="USD per 1M output tokens.")

    def handle(self, *args, **options):
        model = options["model"] or settings.LLM_MODEL

        if options["input"] is not None and options["output"] is not None:
            price_in, price_out, note = options["input"], options["output"], "Set manually."
        elif model in KNOWN_PRICES:
            price_in, price_out, note = KNOWN_PRICES[model]
        else:
            self.stderr.write(
                self.style.ERROR(
                    f"No known price for '{model}'. Pass --input and --output "
                    "(USD per 1M tokens) to set one."
                )
            )
            return

        row, created = ModelPrice.objects.update_or_create(
            model=model,
            defaults={
                "input_usd_per_million": price_in,
                "output_usd_per_million": price_out,
                "notes": note,
            },
        )
        verb = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f"{verb} price for {row}"))
