"""The Orchestrator — the autonomous control loop.

Seeds the initial work from the scope, then repeatedly claims ready tasks, runs
them in parallel through the agents, integrates results back onto the blackboard
(deriving and deduplicating follow-up work), and — when the queue drains or the
time budget is spent — always ends by building the report. One command in; one
report out, with no human in the loop.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from nighttrace import attack_graph, tools
from nighttrace.agents import BinaryAgent, ReconAgent, VerifierAgent, WebAgent
from nighttrace.blackboard import Blackboard
from nighttrace.checks import CheckEngine
from nighttrace.config import Config
from nighttrace.models import AgentResult, Ptes, Status, now_iso
from nighttrace.reasoning import heuristic
from nighttrace.safety import ScopeGuard


class Orchestrator:
    def __init__(self, config: Config, checks: list[dict] | None = None,
                 blackboard: Blackboard | None = None, workers: int = 8):
        self.config = config
        self.bb = blackboard or Blackboard()
        self.guard = ScopeGuard(config, event_sink=self.bb.add_event)
        self.engine = CheckEngine(checks or [], config.flag_pattern)
        self.workers = workers
        self.agents = {
            "recon": ReconAgent(self.bb, self.guard, self.engine, config),
            "web": WebAgent(self.bb, self.guard, self.engine, config),
            "binary": BinaryAgent(self.bb, self.guard, self.engine, config),
            "verify": VerifierAgent(self.bb, self.guard, self.engine, config),
        }
        budget_min = config.limits.max_runtime_minutes * config.tier_settings["budget_mult"]
        self._budget_seconds = budget_min * 60.0
        # Threat-modeling priority boosts accumulated from active hypotheses:
        # by the check they suggest, and by the target they concern.
        self._boost_by_check: dict[str, int] = {}
        self._boost_by_target: dict[str, int] = {}
        # Cooperative cancellation: lets a new run preempt a long one in flight.
        self._cancel = threading.Event()

    def cancel(self) -> None:
        """Ask the control loop to stop after the current batch; run() then
        finishes by building a report from whatever has been gathered so far."""
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # -- public --------------------------------------------------------------
    def run(self) -> dict:
        from nighttrace import reporter  # local import avoids a cycle

        start = time.monotonic()
        deadline = start + self._budget_seconds
        self.bb.set_meta("engagement", self.config.engagement)
        self.bb.set_meta("tier", self.config.tier)
        self.bb.set_meta("started", now_iso())
        self.bb.add_event("orchestrator", "start", Ptes.PRE_ENGAGEMENT.value,
                          f"engagement '{self.config.engagement}' (tier: {self.config.tier}) — scope armed, default-deny active")

        self._seed()
        self._loop(deadline)
        if self._cancel.is_set():
            self.bb.add_event("orchestrator", "cancelled", Ptes.REPORTING.value,
                              "run cancelled — building report from partial results", level="warn")
        attack = attack_graph.build(self.bb)
        self._score_findings(attack)

        self.bb.set_meta("finished", now_iso())
        self.bb.set_meta("duration_seconds", round(time.monotonic() - start, 2))
        self.bb.set_meta("scope_safety", self.guard.summary())
        self.bb.set_meta("score_multiplier", self.config.tier_settings["score_multiplier"])
        self.bb.add_event("reporter", "report", Ptes.REPORTING.value,
                          "run complete — building PTES report")
        return reporter.build(self.bb, self.config, attack)

    # -- phases --------------------------------------------------------------
    def _seed(self) -> None:
        surfaces = self.config.tier_settings["surfaces"]
        if "network" in surfaces or "web" in surfaces:
            for host in self.config.scope.hosts:
                self.bb.enqueue_task(type="recon", ptes=Ptes.INTEL_GATHERING.value,
                                     target={"host": host}, dedupe_key=f"recon:host:{host}")
                if "web" in surfaces:
                    # If specific HTTP(S) ports were configured in scope, seed web directly so
                    # a slow LAN connect scan does not silently prevent the web audit
                    for port in (self.config.scope.ports or []):
                        if port in tools.HTTP_PORTS or port in tools.HTTPS_PORTS:
                            self.bb.enqueue_task(type="web", ptes=Ptes.VULN_ANALYSIS.value,
                                                 target={"host": host, "port": port},
                                                 dedupe_key=f"web:{host}:{port}")
            for net in self.config.scope.networks:
                self.bb.enqueue_task(type="recon", ptes=Ptes.INTEL_GATHERING.value,
                                     target={"network": net}, dedupe_key=f"recon:net:{net}")
        if "binary" in surfaces:
            for path in self.config.scope.binaries:
                if self.guard.check_binary(path).allowed:
                    self.bb.enqueue_task(type="binary", ptes=Ptes.VULN_ANALYSIS.value,
                                         target={"path": path}, dedupe_key=f"binary:{path}")

    def _loop(self, deadline: float) -> None:
        pool = ThreadPoolExecutor(max_workers=self.workers)
        try:
            while time.monotonic() < deadline and not self._cancel.is_set():
                batch = heuristic.prioritize(self.bb.claim_pending(self.workers))
                if not batch:
                    break
                futures = {pool.submit(self._run_task, t): t for t in batch}
                for fut in as_completed(futures):
                    task = futures[fut]
                    try:
                        self._integrate(task, fut.result())
                        self.bb.finish_task(task["id"], "done")
                    except Exception as exc:  # resilience: one bad task never stalls the run
                        attempts = (task.get("attempts") or 0) + 1
                        if attempts <= 1:
                            self.bb.finish_task(task["id"], "pending", attempts)  # one retry
                        else:
                            self.bb.finish_task(task["id"], "failed", attempts)
                            self.bb.add_event("orchestrator", "task_failed", task.get("ptes", ""),
                                              f"task {task['id']} ({task['type']}) failed: {exc.__class__.__name__}",
                                              level="error")
        finally:
            pool.shutdown(wait=True)

    def _run_task(self, task: dict) -> AgentResult:
        agent = self.agents.get(task["type"])
        if agent is None:
            raise ValueError(f"no agent for task type {task['type']!r}")
        return agent.handle(task)

    def _integrate(self, task: dict, result: AgentResult) -> None:
        for a in result.assets:
            self.bb.upsert_asset(a.host, a.port, a.service, a.product, a.surface, a.data)

        # Threat modeling (PTES phase 3): record hypotheses first so the boosts
        # they carry are available to the verify/follow-up tasks created below.
        self._absorb_hypotheses(result.hypotheses)

        for f in result.findings:
            fid, is_new = self.bb.add_finding(
                title=f.title, type=f.type, surface=f.surface, ptes=f.ptes,
                severity=f.severity, status=f.status, description=f.description,
                fix=f.fix, asset_host=f.asset_host, asset_port=f.asset_port,
                check_id=f.check_id, data=f.data)
            if not is_new:
                continue
            for ev in f.evidence:
                self.bb.add_evidence(fid, ev.get("kind", "probe"), ev.get("content", ""))
            # Suspected findings that came from a check get an automatic verification task.
            if f.status == Status.SUSPECTED.value and f.check_id:
                if f.surface == "binary":
                    target = {"path": (f.data or {}).get("path")}
                else:
                    target = {"host": f.asset_host, "port": f.asset_port,
                              "base_url": (f.data or {}).get("base_url")}
                vdata = {"finding_id": fid, "check_id": f.check_id}
                boost = self._boost_for(check_id=f.check_id, host=f.asset_host, port=f.asset_port)
                if boost:
                    vdata["priority_boost"] = boost
                self.bb.enqueue_task(type="verify", ptes=Ptes.EXPLOITATION.value,
                                     target=target, check_id=f.check_id,
                                     dedupe_key=f"verify:{fid}", data=vdata)

        for fu in result.followups:
            fdata = dict(fu.data or {})
            boost = self._boost_for(check_id=fu.check_id, host=fu.target.get("host"),
                                    port=fu.target.get("port"), base_url=fu.target.get("base_url"),
                                    path=fu.target.get("path"))
            if boost:
                fdata["priority_boost"] = max(boost, int(fdata.get("priority_boost") or 0))
            self.bb.enqueue_task(type=fu.type, ptes=fu.ptes, target=fu.target,
                                 check_id=fu.check_id, dedupe_key=fu.dedupe_key, data=fdata)

    def _absorb_hypotheses(self, hyps: list[dict]) -> None:
        """Record each formulated hypothesis as a threat-modeling event and fold
        its priority_boost into the per-check and per-target boost maps."""
        for h in hyps or []:
            self.bb.add_event(
                "orchestrator", "hypothesis_formulated", Ptes.THREAT_MODELING.value,
                f"Formulated hypothesis: {h['title']} for {h['target']} "
                f"(Confidence: {int(h.get('confidence', 0) * 100)}%) — {h['rationale']}",
                data=h)
            boost = int(h.get("priority_boost") or 0)
            for cid in h.get("suggested_checks") or []:
                self._boost_by_check[cid] = max(self._boost_by_check.get(cid, 0), boost)
            tgt = h.get("target")
            if tgt:
                self._boost_by_target[tgt] = max(self._boost_by_target.get(tgt, 0), boost)

    def _boost_for(self, *, check_id: str | None = None, host: str | None = None,
                   port: int | None = None, base_url: str | None = None,
                   path: str | None = None) -> int:
        """Highest boost any active hypothesis gives this work, matched by the
        check it would run or the target it concerns."""
        keys = [base_url, f"{host}:{port}" if host and port else None, host, path]
        candidates = [self._boost_by_target.get(k, 0) for k in keys if k]
        if check_id:
            candidates.append(self._boost_by_check.get(check_id, 0))
        return max(candidates, default=0)

    def _score_findings(self, attack: dict) -> None:
        on_path: set[int] = set()
        for e in attack.get("edges", []):
            if e.get("finding_id"):
                on_path.add(e["finding_id"])
        for p in attack.get("paths", []):
            for step in p["steps"]:
                if step.get("finding_id"):
                    on_path.add(step["finding_id"])
        for f in self.bb.list_findings():
            confirmed = f["status"] == Status.CONFIRMED.value
            score = heuristic.score_finding(f["severity"], confirmed=confirmed,
                                            on_attack_path=f["id"] in on_path)
            self.bb.update_finding(f["id"], score=score)
