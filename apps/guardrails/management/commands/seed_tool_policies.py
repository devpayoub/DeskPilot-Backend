from django.core.management.base import BaseCommand

from apps.guardrails.policy import seed_policies_from_registry


class Command(BaseCommand):
    help = (
        "Create a ToolPolicy row for every registered tool that lacks one. "
        "Existing rows are never modified — the console is the source of truth "
        "once a row exists."
    )

    def handle(self, *args, **options):
        created = seed_policies_from_registry()
        if created:
            self.stdout.write(self.style.SUCCESS(f"{created} tool policy row(s) created."))
        else:
            self.stdout.write("All registered tools already have a policy row.")
