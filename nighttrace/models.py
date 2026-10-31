"""Core data types shared across the engine.

These are the vocabulary of the blackboard: assets (what we found), findings
(weaknesses, with a proof lifecycle), tasks (work to do), events (the audit
trail / live feed) and attack-graph edges (how findings chain together).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def now_iso() -> str:
    """UTC timestamp, ISO-8601 — used on every row so a run is reproducible."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Surface(str, Enum):
    NETWORK = "network"
    WEB = "web"
    BINARY = "binary"


class Ptes(str, Enum):
    """The seven PTES phases. Every task, finding and event carries one."""
    PRE_ENGAGEMENT = "pre_engagement"
    INTEL_GATHERING = "intelligence_gathering"
    THREAT_MODELING = "threat_modeling"
    VULN_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class Status(str, Enum):
    """Finding lifecycle: only CONFIRMED findings reach the report."""
    SUSPECTED = "Suspected"
    VERIFYING = "Verifying"
    CONFIRMED = "Confirmed"
    REFUTED = "Refuted"
    REPORTED = "Reported"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class TaskType(str, Enum):
    RECON = "recon"
    WEB = "web"
    BINARY = "binary"
    VERIFY = "verify"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AssetRec:
    """A discovered host/port/service, or a provided binary."""
    host: str
    port: int | None = None
    service: str | None = None
    product: str | None = None
    surface: str = Surface.NETWORK.value
    data: dict = field(default_factory=dict)


@dataclass
class FindingRec:
    """A potential weakness. Starts Suspected; the verifier proves or refutes it."""
    title: str
    type: str
    surface: str
    ptes: str
    severity: str
    status: str = Status.SUSPECTED.value
    description: str = ""
    fix: str = ""
    asset_host: str | None = None
    asset_port: int | None = None
    check_id: str | None = None
    evidence: list[dict] = field(default_factory=list)
    data: dict = field(default_factory=dict)


@dataclass
class TaskSpec:
    """A unit of work for an agent. dedupe_key makes work idempotent."""
    type: str
    ptes: str
    target: dict
    dedupe_key: str
    check_id: str | None = None
    data: dict = field(default_factory=dict)


@dataclass
class AgentResult:
    """What an agent hands back to the orchestrator for integration."""
    assets: list[AssetRec] = field(default_factory=list)
    findings: list[FindingRec] = field(default_factory=list)
    followups: list[TaskSpec] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
