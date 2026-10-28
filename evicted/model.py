"""Core data types shared across evicted."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    VULNERABLE = "vulnerable"   # the access-removal failed: the bug is present
    OK = "ok"                   # access was correctly denied
    SKIPPED = "skipped"         # adapter/target can't support this check
    ERROR = "error"             # the check could not run


# Ranking so reports can sort findings worst-first.
_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class Account:
    """One user account under test. These must be YOUR accounts."""
    id: str
    secret: str = ""          # password/token/etc., meaning is adapter-specific
    label: str = ""           # human label, e.g. "owner", "guest"


@dataclass(frozen=True)
class Device:
    """A device under test, identified the way the target's API identifies it."""
    id: str
    label: str = ""


@dataclass
class ActionResult:
    """Outcome of asking the target to perform a device action."""
    allowed: bool
    detail: str = ""

    def __bool__(self) -> bool:  # lets callers write `if result:`
        return self.allowed


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    status: Status
    detail: str = ""
    evidence: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.status == Status.VULNERABLE


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        # vulnerable first, then by severity, so the worst is at the top
        return sorted(
            self.findings,
            key=lambda f: (f.status != Status.VULNERABLE, _SEV_ORDER[f.severity]),
        )

    @property
    def vulnerable(self) -> list[Finding]:
        return [f for f in self.findings if f.is_vulnerable]
