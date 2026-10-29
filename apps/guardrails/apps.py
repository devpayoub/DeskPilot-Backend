from django.apps import AppConfig


class GuardrailsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.guardrails"

    def ready(self) -> None:
        """Populate the tool registry once, at startup.

        Pure in-memory work — no database access, which Django forbids here.
        Idempotent, so repeated imports cannot double-register a tool.
        """
        from toolcore.tools import register_all

        register_all()
