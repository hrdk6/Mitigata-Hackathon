"""Exploitation & Verification agent (PTES: Exploitation).

Takes a Suspected finding and re-tests it with a safe, non-destructive action
that captures evidence. On success the finding becomes Confirmed; otherwise it
is Refuted and dropped — which is what keeps the false-alarm rate near zero.
Capturing a planted flag is recorded as its own Confirmed finding (bonus B-1).
"""
from __future__ import annotations

from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, FindingRec, Ptes, Status, Surface


class VerifierAgent(Agent):
    name = "verifier"

    def handle(self, task: dict) -> AgentResult:
        res = AgentResult()
        d = task.get("data") or {}
        fid = d.get("finding_id")
        cid = d.get("check_id")
        finding = self.bb.get_finding(fid) if fid else None
        if not finding:
            return res

        self.bb.update_finding(fid, status=Status.VERIFYING.value)
        self.emit("verify", Ptes.EXPLOITATION.value, f"verifying #{fid}: {finding['title']}")

        check = next((c for c in self.engine.checks if c.get("id") == cid), None)
        if check is None:
            self.bb.update_finding(fid, status=Status.REFUTED.value)
            self.emit("verify", Ptes.EXPLOITATION.value,
                      f"#{fid} refuted: no check available to prove it", level="warn")
            return res

        outcome = self.engine.verify(check, finding, task.get("target") or {}, self.guard)
        for ev in outcome.evidence:
            self.bb.add_evidence(fid, "verification", ev)

        if not outcome.confirmed:
            self.bb.update_finding(fid, status=Status.REFUTED.value)
            self.emit("verify", Ptes.EXPLOITATION.value, f"#{fid} REFUTED: {finding['title']}", level="warn")
            return res

        merged = {**(finding.get("data") or {}), **(outcome.data or {})}
        self.bb.update_finding(fid, status=Status.CONFIRMED.value, data=merged)
        self.emit("verify", Ptes.EXPLOITATION.value,
                  f"#{fid} CONFIRMED: {finding['title']}", data={"finding_id": fid})

        flag = (outcome.data or {}).get("flag")
        if flag:
            res.findings.append(FindingRec(
                title="Planted flag captured", type="flag_captured",
                surface=finding.get("surface", Surface.WEB.value),
                ptes=Ptes.POST_EXPLOITATION.value, severity="critical",
                status=Status.CONFIRMED.value,
                description=f"A planted flag was read as proof of access: {flag}",
                fix="Not applicable — this proves a protected asset was reachable.",
                asset_host=finding.get("asset_host"), asset_port=finding.get("asset_port"),
                evidence=[{"kind": "flag", "content": flag}],
                data={"flag": flag, "via": f"admin:{finding.get('asset_host')}:{finding.get('asset_port')}"}))
            self.emit("flag", Ptes.POST_EXPLOITATION.value, f"captured flag {flag}", data={"finding_id": fid})
        return res
