"""Binary agent (PTES: Vulnerability Analysis).

Static, read-only inspection of the provided binaries: extracts strings and
runs the declarative binary checks (hard-coded credentials, unsafe functions,
missing exploit mitigations). Nothing is executed.
"""
from __future__ import annotations

from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, FindingRec, Ptes, Surface
from nighttrace.reasoning import hypothesis


class BinaryAgent(Agent):
    name = "binary"

    def handle(self, task: dict) -> AgentResult:
        path = task["target"]["path"]
        res = AgentResult()
        res.assets.append(AssetRec(host=path, port=None, service="binary",
                                   surface=Surface.BINARY.value, data={"path": path}))
        # A present executable is a strong signal for embedded plaintext secrets.
        res.hypotheses.extend(h.as_dict() for h in
                              hypothesis.generate_hypotheses("binary_present", path))

        target = {"path": path}
        checks = self.engine.applicable("binary", {})
        if not checks:
            self.emit("binary_scan", Ptes.VULN_ANALYSIS.value,
                      f"{path}: no binary checks configured", level="warn")
            return res

        count = 0
        for check in checks:
            for o in self.engine.probe(check, target, self.guard):
                count += 1
                res.findings.append(FindingRec(
                    title=o.title, type=o.type, surface=Surface.BINARY.value,
                    ptes=check.get("ptes_phase", Ptes.VULN_ANALYSIS.value),
                    severity=o.severity, description=o.description, fix=o.fix,
                    asset_host=path, asset_port=None, check_id=check.get("id"),
                    evidence=[{"kind": "probe", "content": o.evidence}], data={**o.data}))
                self.emit("finding", check.get("ptes_phase", Ptes.VULN_ANALYSIS.value),
                          f"{path}: suspected {o.type} — {o.title}")
        self.emit("binary_scan", Ptes.VULN_ANALYSIS.value,
                  f"{path}: analysed, {count} suspected finding(s)")
        return res
