"""Hypothesis-driven threat modeling (PTES Phase 3: Threat Modeling).

Rather than testing every possibility with equal weight, the engine reasons
*ahead* of itself: the moment a signal appears (a login portal, a live web root,
a binary, a query parameter, a leaked secret) it formulates a falsifiable
hypothesis about the most frequently-appearing class of weakness for that
signal, with a confidence drawn from how often that pattern shows up in real
lab/pentest environments. Each hypothesis carries a ``priority_boost`` so the
orchestrator concentrates the agents on the high-yield work first, and a
``suggested_checks`` list naming the declarative checks that would prove or
refute it. A hypothesis is FORMULATED when raised and VALIDATED once a finding
it predicted is confirmed with captured evidence (otherwise it simply never
validates -- it is a prediction, never a claim).

This is deliberately deterministic: the same signals always yield the same
hypotheses, so a run stays reproducible and explainable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Hypothesis:
    """A falsifiable prediction about a likely weakness, raised from one signal."""
    id: str
    title: str
    category: str
    rationale: str
    target: str
    confidence: float          # 0.80-0.95: how often this pattern appears in practice
    priority_boost: int        # how much to move its checks up the queue
    suggested_checks: list[str] = field(default_factory=list)
    status: str = "FORMULATED"  # -> "VALIDATED" or "REJECTED"

    def as_dict(self) -> dict:
        return asdict(self)


# The Top-5 frequently-appearing vulnerability patterns, keyed by the signal
# that triggers them. Confidence reflects real-world base rates in lab/CTF and
# professional engagements; priority_boost ranks how aggressively to chase it.
_TEMPLATES: dict[str, list[dict]] = {
    "http_login": [dict(
        tid="HYP-AUTH-DEFAULT", title="Default Administrative Credentials",
        category="authentication", confidence=0.90, priority_boost=40,
        suggested_checks=["web-default-credentials"],
        rationale="Management portals frequently ship with default credentials "
                  "(admin:admin, root:root).")],
    "http_alive": [dict(
        tid="HYP-CONFIG-LEAK", title="Exposed Version Control & Config Secrets",
        category="information-disclosure", confidence=0.85, priority_boost=35,
        suggested_checks=["web-git-exposure", "web-sensitive-paths", "web-directory-listing"],
        rationale="Web roots frequently expose undeleted /.git or /.env files.")],
    "binary_present": [dict(
        tid="HYP-BINARY-SECRETS", title="Hardcoded Binary Secrets",
        category="secrets", confidence=0.88, priority_boost=30,
        suggested_checks=["bin-weak-strings"],
        rationale="Compiled binaries often embed plaintext credentials or embedded flags.")],
    "params_found": [dict(
        tid="HYP-INPUT-REFLECTION", title="Unsanitized Input Reflection",
        category="injection", confidence=0.82, priority_boost=25,
        suggested_checks=["web-reflected-input", "web-sql-injection", "web-path-traversal"],
        rationale="User input parameters frequently lack context-aware output encoding.")],
    "creds_leaked": [dict(
        tid="HYP-CRED-REUSE", title="Cross-Surface Credential Reuse",
        category="credential-reuse", confidence=0.92, priority_boost=45,
        suggested_checks=["web-default-credentials"],
        rationale="Passwords found in code or config are frequently valid on live "
                  "network services.")],
}


def generate_hypotheses(signal: str, target: str) -> list[Hypothesis]:
    """Formulate the hypotheses a given signal implies, scoped to one target."""
    out: list[Hypothesis] = []
    for t in _TEMPLATES.get(signal, []):
        out.append(Hypothesis(
            id=f"{t['tid']}:{target}", title=t["title"], category=t["category"],
            rationale=t["rationale"], target=target, confidence=t["confidence"],
            priority_boost=t["priority_boost"],
            suggested_checks=list(t["suggested_checks"])))
    return out


def template_for_check(check_id: str | None) -> dict | None:
    """Map a check back to the hypothesis template it would validate (used when a
    finding is confirmed, to raise the matching ``hypothesis_validated`` event)."""
    if not check_id:
        return None
    for templates in _TEMPLATES.values():
        for t in templates:
            if check_id in t["suggested_checks"]:
                return t
    return None
