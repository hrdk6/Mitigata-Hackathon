"""The REST API (FR-7) and the dashboard host (bonus B-5).

Read-only views over the blackboard: discovered targets, findings with evidence,
the attack path, the full report (md/html/json), a self-score, and an events
feed the dashboard polls for the live view.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Body, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from nighttrace import attack_graph, netdiscover, reporter, scoring
from nighttrace.blackboard import Blackboard
from nighttrace.config import TIERS, Config, load_scope

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
_DASHBOARD = _DASHBOARD_DIR / "index.html"
_DISCOVER = _DASHBOARD_DIR / "discover.html"
_SCOPE_EDITOR = _DASHBOARD_DIR / "scope.html"
_ROOT = Path(__file__).resolve().parent.parent.parent
_CONFIG = _ROOT / "config"


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

    @app.get("/hypotheses")
    def hypotheses() -> dict:
        return reporter.collect_hypotheses(bb.list_events(0, 100000))

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

    # -- network discovery (pre-engagement): find hosts on the local WiFi/LAN --
    @app.get("/discover", response_class=HTMLResponse)
    def discover_page() -> str:
        try:
            return _DISCOVER.read_text(encoding="utf-8")
        except OSError:
            return "<h1>NightTrace</h1><p>Discovery asset missing.</p>"

    @app.get("/network/interfaces")
    def network_interfaces() -> dict:
        return {"networks": netdiscover.local_networks()}

    @app.post("/network/scan")
    def network_scan(payload: dict = Body(default={})):
        cidr = (payload or {}).get("cidr")
        if not cidr:
            nets = netdiscover.local_networks()
            if not nets:
                return JSONResponse({"error": "could not detect a local network; pass a cidr"}, status_code=400)
            cidr = nets[0]["cidr"]
        try:
            timeout = float((payload or {}).get("timeout", 0.3))
            return netdiscover.scan_network(cidr, timeout=max(0.1, min(timeout, 2.0)))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    # -- scope calibration (edit config/scope.yaml from the UI) --------------
    @app.get("/scope-editor", response_class=HTMLResponse)
    def scope_editor_page() -> str:
        try:
            return _SCOPE_EDITOR.read_text(encoding="utf-8")
        except OSError:
            return "<h1>NightTrace</h1><p>Scope editor asset missing.</p>"

    @app.get("/scope")
    def get_scope():
        """Return config/scope.yaml for the form to prefill, or a template seeded
        from the running engagement when no file exists yet."""
        import yaml
        dest = _CONFIG / "scope.yaml"
        if dest.is_file():
            try:
                return {"exists": True, "path": str(dest),
                        "scope": yaml.safe_load(dest.read_text(encoding="utf-8")) or {}}
            except Exception as exc:  # malformed file: let the UI show it
                return {"exists": True, "path": str(dest), "error": str(exc)}
        return {"exists": False, "path": str(dest), "scope": {
            "engagement": config.engagement, "tier": config.tier,
            "scope": {"networks": [], "hosts": [], "binaries": [], "exclude": [], "ports": []},
            "limits": {"max_runtime_minutes": config.limits.max_runtime_minutes,
                       "rate_limit_pps": config.limits.rate_limit_pps, "destructive": False},
            "flags": {"pattern": config.flag_pattern}}}

    @app.post("/scope")
    def save_scope(payload: dict = Body(default={})):
        """Validate a full scope payload and write config/scope.yaml. Destructive
        mode is forced off — the engine is non-destructive by design."""
        import ipaddress
        import yaml
        payload = payload or {}
        errors: list[str] = []

        def _clean(v):
            return [s.strip() for s in (v or []) if str(s).strip()]

        networks, hosts = _clean(payload.get("networks")), _clean(payload.get("hosts"))
        binaries, exclude = _clean(payload.get("binaries")), _clean(payload.get("exclude"))
        for n in networks:
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError:
                errors.append(f"invalid network CIDR: {n}")

        tier = str(payload.get("tier", "breach")).lower()
        if tier not in TIERS:
            errors.append(f"unknown tier '{tier}' (choose {', '.join(sorted(TIERS))})")

        ports: list[int] = []
        for p in (payload.get("ports") or []):
            try:
                pi = int(p)
                ports.append(pi) if 1 <= pi <= 65535 else errors.append(f"port out of range: {p}")
            except (TypeError, ValueError):
                errors.append(f"invalid port: {p}")

        if not (networks or hosts or binaries):
            errors.append("scope is empty — add at least one network, host, or binary")

        try:
            mrt = float(payload.get("max_runtime_minutes", 20))
            if mrt <= 0:
                errors.append("max_runtime_minutes must be > 0")
        except (TypeError, ValueError):
            errors.append("invalid max_runtime_minutes"); mrt = 20.0
        try:
            rpp = int(payload.get("rate_limit_pps", 50))
            if rpp <= 0:
                errors.append("rate_limit_pps must be > 0")
        except (TypeError, ValueError):
            errors.append("invalid rate_limit_pps"); rpp = 50

        if errors:
            return JSONResponse({"errors": errors}, status_code=400)

        doc = {
            "engagement": str(payload.get("engagement") or "engagement"),
            "tier": tier,
            "scope": {"networks": networks, "hosts": hosts, "binaries": binaries,
                      "exclude": exclude, "ports": ports},
            "limits": {"max_runtime_minutes": mrt, "rate_limit_pps": rpp, "destructive": False},
            "flags": {"pattern": config.flag_pattern},
        }
        text = yaml.safe_dump(doc, sort_keys=False)
        _CONFIG.mkdir(parents=True, exist_ok=True)
        dest = _CONFIG / "scope.yaml"
        dest.write_text(text, encoding="utf-8")
        try:  # confirm the engine will accept what we just wrote
            load_scope(dest)
        except Exception as exc:
            return JSONResponse({"errors": [f"written but failed validation: {exc}"], "yaml": text},
                                status_code=400)
        return {"path": str(dest), "yaml": text,
                "run": "python -m nighttrace run --scope config/scope.yaml --out reports"}

    @app.post("/network/scope")
    def network_scope(payload: dict = Body(default={})):
        payload = payload or {}
        ips = [str(x).strip() for x in payload.get("ips", []) if str(x).strip()]
        if not ips:
            return JSONResponse({"error": "select at least one host"}, status_code=400)
        _CONFIG.mkdir(parents=True, exist_ok=True)
        dest = _CONFIG / "scope.yaml"
        text = netdiscover.write_scope(
            dest, ips,
            cidr=payload.get("cidr"),
            engagement=payload.get("engagement") or "hackathon-engagement",
            tier=payload.get("tier") or "breach",
            exclude=payload.get("exclude") or [],
        )
        return {"path": str(dest), "yaml": text,
                "run": "python -m nighttrace run --scope config/scope.yaml --out reports"}

    return app
