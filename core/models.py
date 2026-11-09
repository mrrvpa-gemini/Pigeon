"""Core data models for findings and validation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    """Represents a non-destructive security finding."""

    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    target: str
    category: str = "general"
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "target": self.target,
            "category": self.category,
            "timestamp_utc": self.timestamp_utc,
        }


@dataclass
class ValidationResult:
    """Represents an evidence-based validation outcome."""

    title: str
    description: str
    evidence: str
    status: str
    validation_note: str
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "status": self.status,
            "validation_note": self.validation_note,
            "timestamp_utc": self.timestamp_utc,
        }
