from rest_framework import serializers

from apps.helpdesk.models import Ticket, TicketMessage

from .models import AgentRun, AgentStep


class TicketMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketMessage
        fields = ("id", "author_type", "author_name", "body", "is_internal", "created_at")
        read_only_fields = fields


class TicketListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = (
            "id",
            "number",
            "subject",
            "status",
            "priority",
            "category",
            "ai_disposition",
            "ai_confidence",
            "created_at",
        )
        read_only_fields = fields


class TicketDetailSerializer(serializers.ModelSerializer):
    messages = TicketMessageSerializer(many=True, read_only=True)
    latest_run_id = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = (
            "id",
            "number",
            "subject",
            "body",
            "requester_name",
            "requester_email",
            "device_hostname",
            "status",
            "priority",
            "category",
            "ai_disposition",
            "ai_summary",
            "ai_diagnosis",
            "ai_confidence",
            "messages",
            "latest_run_id",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_latest_run_id(self, obj) -> int | None:
        run = obj.latest_run
        return run.pk if run else None


class TicketCreateSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=255)
    body = serializers.CharField()
    requester_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    requester_email = serializers.EmailField(required=False, allow_blank=True)
    device_hostname = serializers.CharField(max_length=120, required=False, allow_blank=True)
    priority = serializers.ChoiceField(
        choices=Ticket.Priority.choices, required=False, default=Ticket.Priority.P3
    )


class AgentStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentStep
        fields = (
            "id",
            "step_no",
            "thought",
            "tool_name",
            "tool_risk",
            "validated_args",
            "result",
            "status",
            "error_code",
            "latency_ms",
            "tokens_in",
            "tokens_out",
            "cost_usd",
            "created_at",
        )
        read_only_fields = fields


class AgentRunSerializer(serializers.ModelSerializer):
    duration_ms = serializers.IntegerField(read_only=True)
    steps = AgentStepSerializer(many=True, read_only=True)

    class Meta:
        model = AgentRun
        fields = (
            "id",
            "ticket",
            "status",
            "trigger",
            "model",
            "prompt_version",
            "iterations",
            "tool_calls",
            "prompt_tokens",
            "completion_tokens",
            "cost_usd",
            "duration_ms",
            "final_result",
            "pending_question",
            "error",
            "started_at",
            "finished_at",
            "created_at",
            "steps",
        )
        read_only_fields = fields


class AgentRunSummarySerializer(serializers.ModelSerializer):
    """Run without the step list — used where the trace would be noise."""

    duration_ms = serializers.IntegerField(read_only=True)

    class Meta:
        model = AgentRun
        fields = (
            "id",
            "ticket",
            "status",
            "iterations",
            "tool_calls",
            "cost_usd",
            "duration_ms",
            "error",
            "created_at",
        )
        read_only_fields = fields
