"""Run the golden set.

    python manage.py run_evals --mode oracle          # verify the harness
    python manage.py run_evals --mode replay          # recorded model, free
    python manage.py run_evals --mode live --limit 10 # real model, costs money
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from apps.evals.models import EvalRun
from apps.evals.runner import run_all


class Command(BaseCommand):
    help = "Run the golden-set evaluation and record the metrics."

    def add_arguments(self, parser):
        parser.add_argument(
            "--mode",
            default=EvalRun.Mode.ORACLE,
            choices=[choice for choice, _ in EvalRun.Mode.choices],
            help="oracle = harness self-check; replay = cassettes; live = real model.",
        )
        parser.add_argument("--limit", type=int, default=None, help="Only the first N cases.")
        parser.add_argument("--notes", default="", help="Free-text note stored on the run.")
        parser.add_argument(
            "--control",
            action="store_true",
            help="Negative control: a deliberately lazy agent. The gates MUST fail.",
        )

    def handle(self, *args, **options):
        mode = options["mode"]
        if mode == EvalRun.Mode.ORACLE:
            self.stdout.write(
                self.style.WARNING(
                    "oracle mode: model decisions are scripted from the dataset. "
                    "This verifies the harness, not a model."
                )
            )

        run = run_all(
            mode=mode,
            limit=options["limit"],
            notes=options["notes"],
            control=options["control"],
        )

        metrics = run.metrics
        self.stdout.write("")
        self.stdout.write(f"run #{run.pk}  mode={run.mode}  cases={run.case_count}")
        self.stdout.write(f"  triage accuracy      {metrics.get('triage_accuracy')}")
        self.stdout.write(f"  disposition accuracy {metrics.get('disposition_accuracy')}")
        self.stdout.write(f"  tool precision/recall {metrics['tools']['precision']} / {metrics['tools']['recall']}")
        self.stdout.write(f"  unsafe action rate   {metrics.get('unsafe_action_rate')}")
        self.stdout.write(f"  p95 latency          {metrics['latency']['p95_ms']} ms")
        self.stdout.write(f"  gates passed         {metrics.get('gates_passed')}")

        if not metrics.get("gates_passed"):
            self.stdout.write(self.style.ERROR("  GATE FAILED"))
            self.stdout.write(json.dumps(metrics.get("gates"), indent=2))
