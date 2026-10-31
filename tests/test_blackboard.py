from nighttrace.blackboard import Blackboard
from nighttrace.models import Status


def test_asset_dedupe():
    bb = Blackboard()
    i1, new1 = bb.upsert_asset("h", 80, "http", None, "network")
    i2, new2 = bb.upsert_asset("h", 80, "http", None, "network")
    assert new1 and not new2 and i1 == i2


def test_task_dedupe():
    bb = Blackboard()
    _, new1 = bb.enqueue_task(type="web", ptes="x", target={}, dedupe_key="k")
    _, new2 = bb.enqueue_task(type="web", ptes="x", target={}, dedupe_key="k")
    assert new1 and not new2


def test_claim_is_atomic():
    bb = Blackboard()
    for i in range(3):
        bb.enqueue_task(type="recon", ptes="x", target={}, dedupe_key=f"k{i}")
    first = bb.claim_pending(10)
    second = bb.claim_pending(10)
    assert len(first) == 3 and second == []


def test_finding_lifecycle_and_evidence():
    bb = Blackboard()
    fid, new = bb.add_finding(title="t", type="x", surface="web", ptes="exploitation", severity="high")
    assert new
    bb.add_evidence(fid, "verification", "proof captured")
    bb.update_finding(fid, status=Status.CONFIRMED.value, score=48.0)
    f = bb.get_finding(fid)
    assert f["status"] == Status.CONFIRMED.value and f["score"] == 48.0
    assert f["evidence"][0]["content"] == "proof captured"
