from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    PASS = "pass"

    @property
    def weight(self) -> float:
        return {self.CRITICAL: 2.0, self.WARNING: 0.7, self.INFO: 0.0, self.PASS: 0.0}[self]

    @property
    def color(self) -> str:
        return {
            self.CRITICAL: "red bold",
            self.WARNING: "yellow",
            self.INFO: "cyan",
            self.PASS: "green",
        }[self]

    @property
    def icon(self) -> str:
        return {self.CRITICAL: "x", self.WARNING: "!", self.INFO: "-", self.PASS: "*"}[self]


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    remediation: str = ""


@dataclass
class CheckResult:
    name: str
    icon: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.PASS
        return min(self.findings, key=lambda f: -f.severity.weight).severity

    @property
    def deductions(self) -> float:
        return sum(f.severity.weight for f in self.findings if f.severity != Severity.PASS)
