"""Self-scoring harness — grade a run against the organizers' ground truth.

The rubric is public, so NightTrace can measure itself: coverage, findings,
verified share, false-alarm rate, stray probes, run time and autonomy, each
graded against the PRD's Good/Great thresholds.
"""
from __future__ import annotations

from nighttrace.blackboard import Blackboard
from nighttrace.config import _load_structured
from nighttrace.models import Status


def _grade(value: float, good: float, great: float, lower_is_better: bool = False) -> str:
    if lower_is_better:
        if value <= great:
            return "Great"
        if value <= good:
            return "Good"
        return "Miss"
    if value >= great:
        return "Great"
    if value >= good:
        return "Good"
    return "Miss"


def compute(bb: Blackboard, ground_truth_path: str) -> dict:
    gt = _load_structured(ground_truth_path)
    planted_services = {str(x) for x in gt.get("services", [])}
    planted_weaknesses = gt.get("weaknesses", []) or []
    planted_flags = {str(x) for x in gt.get("flags", [])}

    # Coverage: planted services we actually found.
    found_services = set()
    for a in bb.list_assets("network"):
        if a.get("port"):
            found_services.add(f"{a['host']}:{a['port']}")
    cov_hits = len(found_services & planted_services) if planted_services else 0
    coverage = cov_hits / len(planted_services) if planted_services else 1.0

    confirmed = bb.list_findings(status=Status.CONFIRMED.value)
    confirmed_types = [(f["type"], f.get("asset_host")) for f in confirmed]

    # Findings: planted weaknesses we confirmed (match by type, and host if given).
    matched = 0
    for w in planted_weaknesses:
        wtype = w.get("type")
        whost = w.get("host")
        if any(t == wtype and (whost is None or whost == h) for t, h in confirmed_types):
            matched += 1
    findings_rate = matched / len(planted_weaknesses) if planted_weaknesses else 1.0

    # Verified: proven vs still only flagged.
    suspected = bb.stats()["suspected"]
    verified_rate = len(confirmed) / max(len(confirmed) + suspected, 1)

    # False alarms: confirmed findings that match nothing planted.
    planted_type_set = {w.get("type") for w in planted_weaknesses}
    false = sum(1 for t, _ in confirmed_types if t not in planted_type_set and t != "flag_captured")
    false_rate = false / max(len(confirmed), 1)

    # Flags.
    captured_flags = {e.get("content") for f in confirmed if f["type"] == "flag_captured"
                      for e in (f.get("evidence") or []) if e.get("kind") == "flag"}
    flag_hits = len(captured_flags & planted_flags) if planted_flags else len(captured_flags)

    safety = bb.get_meta("scope_safety", {}) or {}
    stray = int(safety.get("stray_probe_attempts", 0))
    runtime = float(bb.get_meta("duration_seconds", 0) or 0)

    # Recall & Precision calculations
    recall = findings_rate
    true_positives = len(confirmed) - false
    precision = true_positives / max(len(confirmed), 1)

    return {
        "coverage": {"value": round(coverage, 3), "grade": _grade(coverage, 0.7, 0.9),
                     "detail": f"{cov_hits}/{len(planted_services)} planted services found"},
        "recall": {"value": round(recall, 3), "grade": _grade(recall, 0.6, 0.85),
                   "detail": f"{matched}/{len(planted_weaknesses)} planted weaknesses confirmed (Recall: {round(recall * 100, 1)}%)"},
        "precision": {"value": round(precision, 3), "grade": _grade(precision, 0.7, 0.9),
                      "detail": f"{true_positives}/{max(len(confirmed), 1)} true findings (Precision: {round(precision * 100, 1)}%)"},
        "findings": {"value": round(findings_rate, 3), "grade": _grade(findings_rate, 0.6, 0.85),
                     "detail": f"{matched}/{len(planted_weaknesses)} planted weaknesses confirmed"},
        "verified": {"value": round(verified_rate, 3), "grade": _grade(verified_rate, 0.5, 1.0),
                     "detail": f"{len(confirmed)} confirmed, {suspected} still suspected"},
        "false_alarms": {"value": round(false_rate, 3), "grade": _grade(false_rate, 0.3, 0.1, lower_is_better=True),
                         "detail": f"{false} of {len(confirmed)} confirmed not in ground truth"},
        "scope_safety": {"value": stray, "grade": _grade(stray, 1, 0, lower_is_better=True),
                         "detail": f"{stray} stray probe(s) outside scope"},
        "flags": {"value": flag_hits, "detail": f"{flag_hits} planted flag(s) captured"},
        "run_time": {"value": runtime, "grade": _grade(runtime, 3600, 1200, lower_is_better=True),
                     "detail": f"{runtime}s for a full autonomous run"},
        "autonomy": {"value": "one command", "grade": "Great",
                     "detail": "no human input during the run"},
    }


def render(metrics: dict) -> str:
    lines = ["NightTrace self-score (vs ground truth)", "=" * 42]
    for key, m in metrics.items():
        grade = m.get("grade", "")
        lines.append(f"  {key:<14} {str(m['value']):<10} {grade:<6} - {m['detail']}")
    return "\n".join(lines)
