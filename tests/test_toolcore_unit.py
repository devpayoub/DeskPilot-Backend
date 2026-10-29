"""Pure toolcore tests: no database, no Django, no network."""
from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict, Field

from toolcore import Tool, registry
from toolcore.errors import ToolNotFound, ToolValidationError
from toolcore.redaction import (
    args_hash,
    normalise_text,
    redact_args,
    redact_deep,
    redact_text,
)
from toolcore.risk import RiskClass


@pytest.fixture
def temp_tools():
    """Register throwaway tools and guarantee cleanup even if a test fails."""
    created: list[str] = []

    def _make(**kwargs) -> Tool:
        tool = Tool(**kwargs)
        registry.register(tool)
        created.append(tool.name)
        return tool

    yield _make

    for name in created:
        registry.unregister(name)


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(min_length=1, max_length=20)
    force: bool = False


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------
def test_risk_ordering_and_labels():
    assert RiskClass.READ < RiskClass.WRITE_REVERSIBLE < RiskClass.WRITE_DESTRUCTIVE
    assert RiskClass.READ.label == "READ"
    assert RiskClass.WRITE_DESTRUCTIVE.label == "WRITE_DESTRUCTIVE"


def test_only_writes_require_approval_by_default():
    assert RiskClass.READ.requires_approval_by_default is False
    assert RiskClass.WRITE_REVERSIBLE.requires_approval_by_default is True
    assert RiskClass.WRITE_DESTRUCTIVE.requires_approval_by_default is True


def test_risk_from_label_roundtrip():
    for risk in RiskClass:
        assert RiskClass.from_label(risk.label) is risk
    with pytest.raises(ValueError):
        RiskClass.from_label("NOT_A_RISK")


# ---------------------------------------------------------------------------
# Redaction / hashing
# ---------------------------------------------------------------------------
def test_redact_masks_sensitive_keys_at_any_depth():
    redacted = redact_args(
        {
            "sam": "a.trabelsi",
            "new_password": "hunter2",
            "nested": {"api_key": "sk-123", "keep": "visible"},
        }
    )
    assert redacted["sam"] == "a.trabelsi"
    assert redacted["new_password"] == "***"
    assert redacted["nested"]["api_key"] == "***"
    assert redacted["nested"]["keep"] == "visible"


def test_redact_bounds_long_strings_and_large_lists():
    redacted = redact_args({"blob": "x" * 5000, "many": list(range(50))})
    assert len(redacted["blob"]) < 300
    assert redacted["blob"].endswith("…")
    assert redacted["many"]["omitted_items"] == 30
    assert len(redacted["many"]["items"]) == 20


def test_args_hash_is_order_independent_and_stable():
    a = args_hash({"b": 2, "a": 1})
    b = args_hash({"a": 1, "b": 2})
    assert a == b
    assert len(a) == 64


def test_args_hash_differs_when_a_value_changes():
    assert args_hash({"service": "Spooler"}) != args_hash({"service": "W32Time"})


def test_normalise_text_collapses_whitespace():
    assert normalise_text("  hello \n world  ") == "hello world"


# ---------------------------------------------------------------------------
# Tool validation
# ---------------------------------------------------------------------------
def test_validate_coerces_and_applies_defaults(temp_tools):
    tool = temp_tools(name="t_validate", description="", handler=lambda c, a: a, input_model=_Args)
    assert tool.validate({"service": "Spooler"}) == {"service": "Spooler", "force": False}


def test_validate_rejects_unknown_argument(temp_tools):
    tool = temp_tools(name="t_strict", description="", handler=lambda c, a: a, input_model=_Args)
    with pytest.raises(ToolValidationError):
        tool.validate({"service": "Spooler", "sudo": True})


def test_validate_rejects_out_of_range_value(temp_tools):
    tool = temp_tools(name="t_bounds", description="", handler=lambda c, a: a, input_model=_Args)
    with pytest.raises(ToolValidationError):
        tool.validate({"service": "x" * 50})


def test_validate_rejects_non_object_payload(temp_tools):
    tool = temp_tools(name="t_nonobj", description="", handler=lambda c, a: a, input_model=_Args)
    with pytest.raises(ToolValidationError):
        tool.validate(["not", "a", "dict"])


def test_no_arg_tool_rejects_stray_arguments(temp_tools):
    tool = temp_tools(name="t_noargs", description="", handler=lambda c, a: a)
    assert tool.validate({}) == {}
    with pytest.raises(ToolValidationError):
        tool.validate({"anything": 1})


def test_spec_reports_risk_and_approval(temp_tools):
    tool = temp_tools(
        name="t_spec",
        description="does a thing",
        handler=lambda c, a: None,
        input_model=_Args,
        risk_class=RiskClass.WRITE_DESTRUCTIVE,
    )
    spec = tool.spec()
    assert spec["risk_class"] == "WRITE_DESTRUCTIVE"
    assert spec["requires_approval"] is True
    assert spec["input_schema"]["properties"]["service"]["type"] == "string"


def test_explicit_approval_false_overrides_write_default(temp_tools):
    tool = temp_tools(
        name="t_noapproval",
        description="",
        handler=lambda c, a: None,
        risk_class=RiskClass.WRITE_REVERSIBLE,
        approval_required=False,
    )
    assert tool.spec()["requires_approval"] is False


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_registry_rejects_duplicate_names(temp_tools):
    temp_tools(name="t_dupe", description="", handler=lambda c, a: None)
    with pytest.raises(ValueError, match="Duplicate tool name"):
        registry.register(Tool(name="t_dupe", description="", handler=lambda c, a: None))


def test_register_if_absent_is_idempotent(temp_tools):
    first = temp_tools(name="t_idem", description="", handler=lambda c, a: None)
    second = registry.register_if_absent(Tool(name="t_idem", description="", handler=lambda c, a: None))
    assert second is first


def test_unknown_tool_raises(temp_tools):
    with pytest.raises(ToolNotFound):
        registry.get_tool("definitely_not_registered")


# ---------------------------------------------------------------------------
# Free-text redaction
#
# ``redact_args`` masks by key name. These mask by shape, because provider error
# bodies and SDK exceptions are third-party prose: they land in a database column
# and are rendered in the console, so they need scrubbing before storage.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,secret_fragment",
    [
        ("Incorrect API key provided: sk-test-abcdef0123456789", "sk-test-abcdef0123456789"),
        ("upstream said Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc", "eyJhbGciOiJIUzI1NiJ9"),
        ("connect failed for postgres://deskpilot:hunter2@db:5432/deskpilot", "hunter2"),
        ("provider error: api_key=abc123def456 rejected", "abc123def456"),
        ("bad login: password=Sup3rS3cret!", "Sup3rS3cret!"),
    ],
)
def test_redact_text_masks_credentials_by_shape(text, secret_fragment):
    cleaned = redact_text(text)

    assert secret_fragment not in cleaned
    assert "***" in cleaned


def test_redact_text_masks_a_known_secret_of_any_shape():
    """Patterns cannot cover every provider's key format, so exact values are passed too."""
    odd_key = "zzz-not-a-recognisable-format-42"

    cleaned = redact_text(f"rejected key {odd_key}", secrets=(odd_key,))

    assert odd_key not in cleaned


def test_redact_text_ignores_short_secrets_to_avoid_shredding_prose():
    """Replacing a 3-character 'secret' would mangle ordinary words, not protect anything."""
    assert redact_text("the cab is here", secrets=("cab",)) == "the cab is here"


def test_redact_text_keeps_the_message_readable():
    """Redaction must not destroy the explanation — a blank trace is its own failure."""
    cleaned = redact_text("Incorrect API key provided: sk-test-abcdef0123456789")

    assert cleaned.startswith("Incorrect API key provided")
    assert cleaned.endswith("***")


def test_redact_text_bounds_unbounded_third_party_text():
    cleaned = redact_text("x" * 5000)

    assert len(cleaned) < 1000


def test_redact_deep_reaches_strings_inside_nested_structures():
    entry = {
        "step": 3,
        "observation": {"items": [{"error": "token=abc123def456"}]},
        "ok": True,
    }

    cleaned = redact_deep(entry)

    assert cleaned["step"] == 3
    assert cleaned["ok"] is True
    assert "abc123def456" not in str(cleaned)
    assert "***" in cleaned["observation"]["items"][0]["error"]
