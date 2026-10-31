"""Common base for all agents.

An agent is a stateless worker: it is handed one task plus the shared services
(blackboard, scope guard, check engine, config), does its surface-specific job,
and returns an AgentResult for the orchestrator to integrate.
"""
from __future__ import annotations

from nighttrace.blackboard import Blackboard
from nighttrace.checks import CheckEngine
from nighttrace.config import Config
from nighttrace.models import AgentResult
from nighttrace.safety import ScopeGuard


class Agent:
    name = "agent"

    def __init__(self, bb: Blackboard, guard: ScopeGuard, engine: CheckEngine, config: Config):
        self.bb = bb
        self.guard = guard
        self.engine = engine
        self.config = config

    def emit(self, action: str, ptes: str, message: str, level: str = "info", data: dict | None = None) -> None:
        self.bb.add_event(self.name, action, ptes, message, level, data)

    def handle(self, task: dict) -> AgentResult:  # pragma: no cover - interface
        raise NotImplementedError
