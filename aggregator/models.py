"""Normalized security finding schema shared by every scanner parser."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import hashlib
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def parse(cls, value: Any, default: "Severity" = None) -> "Severity":
        fallback = default or cls.INFO
        normalized = str(value or "").strip().lower()
        aliases = {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "high": cls.HIGH, "error": cls.HIGH,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "warning": cls.MEDIUM, "warn": cls.MEDIUM,
            "low": cls.LOW, "note": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "unknown": cls.INFO,
        }
        return aliases.get(normalized, fallback)


@dataclass(frozen=True, slots=True)
class Finding:
    tool: str
    severity: Severity
    rule_id: str
    title: str
    location: str
    description: str
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool", self.tool.strip().lower())
        object.__setattr__(self, "severity", Severity.parse(self.severity))
        if not self.fingerprint:
            material = "\x1f".join((self.tool, self.rule_id, self.location, self.title))
            object.__setattr__(self, "fingerprint", hashlib.sha256(material.encode("utf-8")).hexdigest()[:20])

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value

