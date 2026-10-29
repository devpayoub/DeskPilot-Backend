from rest_framework import serializers

from .models import ApprovalRequest, ToolInvocation, ToolPolicy


class ApprovalRequestSerializer(serializers.ModelSerializer):
    is_expired = serializers.BooleanField(read_only=True)
    decided_by_email = serializers.EmailField(source="decided_by.email", read_only=True, default=None)

    class Meta:
        model = ApprovalRequest
        fields = (
            "id",
            "run",
            "step_no",
            "tool_name",
            "risk_class",
            "args_redacted",
            "args_hash",
            "rationale",
            "preview",
            "dry_run_ok",
            "status",
            "decided_by",
            "decided_by_email",
            "decided_at",
            "decision_note",
            "expires_at",
            "is_expired",
            "consumed_at",
            "created_at",
        )
        read_only_fields = fields


class ApprovalDecisionSerializer(serializers.Serializer):
    note = serializers.CharField(required=False, allow_blank=True, max_length=2000, default="")


class ToolPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = ToolPolicy
        fields = (
            "id",
            "tool_name",
            "enabled",
            "risk_class",
            "requires_approval",
            "allowed_roles",
            "max_calls_per_run",
            "updated_at",
        )
        read_only_fields = ("id", "tool_name", "updated_at")


class ToolInvocationSerializer(serializers.ModelSerializer):
    is_denial = serializers.BooleanField(read_only=True)

    class Meta:
        model = ToolInvocation
        fields = (
            "id",
            "tool_name",
            "risk_class",
            "actor_type",
            "actor_id",
            "outcome",
            "args_hash",
            "args_redacted",
            "error_code",
            "error_message",
            "duration_ms",
            "trace_id",
            "transport",
            "dry_run",
            "is_denial",
            "created_at",
        )
        read_only_fields = fields
