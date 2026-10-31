"""The REST API (FR-7) and the dashboard host (bonus B-5).

Read-only views over the blackboard: discovered targets, findings with evidence,
the attack path, the full report (md/html/json), a self-score, and an events
feed the dashboard polls for the live view.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from nighttrace import attack_graph, reporter, scoring
from nighttrace.blackboard import Blackboard
from nighttrace.config import Config

_DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"


def create_app(bb: Blackboard, config: Config) -> FastAPI:
    app = FastAPI(title="NightTrace", version="0.1.0",
                  description="Autonomous multi-agent penetration-testing engine (authorized, in-scope only).")

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        try:
            return _DASHBOARD.read_text(encoding="utf-8")
        except OSError:
            return "<h1>NightTrace</h1><p>Dashboard asset missing.</p>"

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "engagement": config.engagement, "tier": config.tier}

    @app.get("/targets")
    def targets() -> dict:
        return {"assets": bb.list_assets(), "stats": bb.stats()}

    @app.get("/targets/{tid}/findings")
    def target_findings(tid: int):
        asset = next((a for a in bb.list_assets() if a["id"] == tid), None)
        if not asset:
            return JSONResponse({"error": "target not found"}, status_code=404)
        return {"target": asset["host"], "port": asset.get("port"),
                "findings": bb.list_findings(asset_host=asset["host"])}

    @app.get("/findings")
    def findings(status: str | None = None):
        return {"findings": bb.list_findings(status=status)}

    @app.get("/findings/{fid}")
    def finding(fid: int):
        f = bb.get_finding(fid)
        if not f:
            return JSONResponse({"error": "finding not found"}, status_code=404)
        return f

    @app.get("/attack-path")
    def attack_path() -> dict:
        return attack_graph.search(bb)

    @app.get("/events")
    def events(since: int = 0, limit: int = 500) -> dict:
        rows = bb.list_events(since_id=since, limit=limit)
        return {"events": rows, "last_id": rows[-1]["id"] if rows else since}

    @app.get("/report")
    def report(format: str = "json"):
        rep = reporter.build(bb, config, attack_graph.search(bb))
        if format == "md":
            return PlainTextResponse(reporter.render_markdown(rep), media_type="text/markdown")
        if format == "html":
            return HTMLResponse(reporter.render_html(rep))
        return JSONResponse(rep)

    @app.get("/score")
    def score(ground_truth: str):
        if not Path(ground_truth).is_file():
            return JSONResponse({"error": f"ground-truth file not found: {ground_truth}"}, status_code=404)
        return scoring.compute(bb, ground_truth)

    return app
