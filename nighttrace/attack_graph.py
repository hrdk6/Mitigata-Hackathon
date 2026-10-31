"""Attack-graph construction and path search (bonus B-2).

Nodes are states an attacker can hold (external, a source leak, admin on a host,
a captured flag). Edges are *confirmed* findings that move between states.
Finding a full attack path is then a breadth-first search from `external` to any
flag/crown-jewel goal node.
"""
from __future__ import annotations

from collections import defaultdict, deque

from nighttrace.blackboard import Blackboard
from nighttrace.models import Status

EXTERNAL = "external"


def link(bb: Blackboard) -> None:
    """Cross-surface chaining: connect findings that reinforce each other.

    A credential leaked by an exposed repo, reused at a login, or hard-coded in a
    binary and reused on the network — this is where separate findings become one
    path. We only ever *link* already-confirmed, evidence-backed findings.
    """
    confirmed = bb.list_findings(status=Status.CONFIRMED.value)
    gits = [f for f in confirmed if f["type"] == "exposed_git" and (f.get("data") or {}).get("leaked_cred")]
    creds = [f for f in confirmed if f["type"] == "default_credentials"]
    bins = [f for f in confirmed if f["type"] == "hardcoded_credential"]

    for c in creds:
        host = c.get("asset_host")
        d = c.get("data") or {}
        used_pw = d.get("password")
        for g in gits:
            if g.get("asset_host") == host:
                leaked = (g.get("data") or {}).get("leaked_cred", "")
                if leaked and (used_pw and leaked.split(":")[-1] == used_pw):
                    d = {**d, "from_leak": True}
                    bb.update_finding(c["id"], data=d)
        for b in bins:
            bpw = (b.get("data") or {}).get("password")
            if bpw and used_pw and bpw == used_pw:
                bd = {**(b.get("data") or {}), "links_to": f"admin:{host}:{c.get('asset_port')}"}
                bb.update_finding(b["id"], data=bd)


def build(bb: Blackboard) -> dict:
    """Turn confirmed findings into graph edges, then search for goal paths."""
    link(bb)
    for f in bb.list_findings(status=Status.CONFIRMED.value):
        host = f.get("asset_host") or "?"
        port = f.get("asset_port")
        ftype = f["type"]
        data = f.get("data") or {}

        if ftype == "exposed_git":
            leak = f"srcleak:{host}"
            bb.add_attack_edge(EXTERNAL, leak, "exposed .git repository", f["id"])
            if data.get("leaked_cred"):
                bb.add_attack_edge(leak, f"creds:{host}", "credentials leaked in repository", f["id"])
        elif ftype == "default_credentials":
            admin = f"admin:{host}:{port}"
            if data.get("from_leak"):
                bb.add_attack_edge(f"creds:{host}", admin, "reuse of leaked credentials", f["id"])
            bb.add_attack_edge(EXTERNAL, admin, f"default credentials on {data.get('path', '/login')}", f["id"])
            if data.get("flag"):
                bb.add_attack_edge(admin, f"flag:{host}", "read planted flag", f["id"])
        elif ftype == "reflected_input":
            bb.add_attack_edge(EXTERNAL, f"webvuln:{host}:{port}", "reflected user input (XSS)", f["id"])
        elif ftype == "hardcoded_credential":
            node = f"bincred:{host}"
            bb.add_attack_edge(EXTERNAL, node, "credential hard-coded in binary", f["id"])
            if data.get("links_to"):
                bb.add_attack_edge(node, data["links_to"], "reuse of hard-coded credential", f["id"])
        elif ftype == "flag_captured":
            bb.add_attack_edge(data.get("via", EXTERNAL), f"flag:{host}", "captured flag", f["id"])

    return search(bb)


def search(bb: Blackboard) -> dict:
    edges = bb.list_attack_edges()
    adj: dict[str, list[tuple[str, str, int | None]]] = defaultdict(list)
    for e in edges:
        adj[e["src"]].append((e["dst"], e["label"], e.get("finding_id")))

    goals = sorted({e["dst"] for e in edges if e["dst"].startswith("flag:")})
    paths = []
    for goal in goals:
        trail = _bfs(adj, EXTERNAL, goal)
        if trail:
            paths.append({"goal": goal, "steps": trail})
    return {"edges": edges, "goals": goals, "paths": paths}


def _bfs(adj, src: str, dst: str) -> list[dict]:
    q: deque[tuple[str, list[dict]]] = deque([(src, [])])
    seen = {src}
    while q:
        node, trail = q.popleft()
        if node == dst:
            return trail
        for nxt, label, fid in adj.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, trail + [{"from": node, "to": nxt, "label": label, "finding_id": fid}]))
    return []
