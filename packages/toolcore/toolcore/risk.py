"""Risk classification for tools.

Risk is a property of the *capability*, decided by the code that declares the
tool and by policy in the database — never by the model. The chokepoint takes the
maximum of the two, so a policy row can raise risk but can never lower it below
what the tool author declared.
"""
from __future__ import annotations

from enum import IntEnum


class RiskClass(IntEnum):
    READ = 0
    WRITE_REVERSIBLE = 1
    WRITE_DESTRUCTIVE = 2

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def is_write(self) -> bool:
        return self >= RiskClass.WRITE_REVERSIBLE

    @property
    def requires_approval_by_default(self) -> bool:
        """Writes need a human by default; individual tools may opt out explicitly."""
        return self.is_write

    @classmethod
    def from_label(cls, label: str) -> "RiskClass":
        try:
            return _BY_LABEL[label.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown risk class '{label}'.") from exc


_LABELS = {
    RiskClass.READ: "READ",
    RiskClass.WRITE_REVERSIBLE: "WRITE_REVERSIBLE",
    RiskClass.WRITE_DESTRUCTIVE: "WRITE_DESTRUCTIVE",
}
_BY_LABEL = {v: k for k, v in _LABELS.items()}

# Convenience aliases used throughout the codebase.
READ = RiskClass.READ
WRITE_REVERSIBLE = RiskClass.WRITE_REVERSIBLE
WRITE_DESTRUCTIVE = RiskClass.WRITE_DESTRUCTIVE
