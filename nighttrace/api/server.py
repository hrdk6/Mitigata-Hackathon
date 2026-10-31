"""The REST API (FR-7) and the dashboard host (bonus B-5).

Views over the blackboard: discovered targets, findings with evidence, the
attack path, the full report (md/html/json), a self-score, and an events feed
the dashboard polls for the live view.

The engine is driven entirely by the calibrated scope (config/scope.yaml) — the
dashboard lets you edit that scope and then press Run. `POST /run` reloads the
scope, scans it into a *fresh* blackboard and swaps it in, so the whole loop —
discover -> edit scope -> run -> watch — happens from the UI, with no demo and
no hardcoded targets.
"""
from __future__ import annotations

import threading
from pathlib import Path

from fastapi import Body, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from nighttrace import attack_graph, netdiscover, reporter, scoring
from nighttrace.blackboard import Blackboard
from nighttrace.config import TIERS, Config, load_checks, load_scope, parse_web_target
from nighttrace.models import now_iso

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
_DASHBOARD = _DASHBOARD_DIR / "index.html"
_DISCOVER = _DASHBOARD_DIR / "discover.html"
_SCOPE_EDITOR = _DASHBOARD_DIR / "scope.html"
_ROOT = Path(__file__).resolve().parent.parent.parent
_CONFIG = _ROOT / "config"
_SCOPE_FILE = _CONFIG / "scope.yaml"
_CHECKS_FILE = _CONFIG / "checks.yaml"


def create_app(bb: Blackboard, config: Config, checks: list[dict] | None = None, *, autostart: bool = False) -> FastAPI:
    app = FastAPI(title="NightTrace", version="0.1.0",
                  description="Autonomous multi-agent penetration-testing engine (authorized, in-scope only).")


    # The engine's live state. The blackboard and config are swapped on each new
    # run, and every read endpoint goes through here so it always reflects the
    # run currently on screen.
    state: dict = {"bb": bb, "config": config, "status": "idle",
                   "started": None, "finished": None, "error": None,
                   "scope_path": None, "thread": None, "orch": None}
    launch_lock = threading.Lock()

    def _running() -> bool:
        t = state["thread"]
        return t is not None and t.is_alive()

    def _launch(cfg: Config, checks: list[dict], target_bb: Blackboard,
                scope_path: str | None = None) -> None:
        """Swap in a (usually fresh) blackboard and run the engagement in the
        background so the dashboard streams it live."""
        from nighttrace.orchestrator import Orchestrator  # local import avoids a cycle

        orch = Orchestrator(cfg, checks, blackboard=target_bb)
        state.update(bb=target_bb, config=cfg, status="running", started=now_iso(),
                     finished=None, error=None, scope_path=scope_path, orch=orch)

        def _work() -> None:
            # A superseded run (preempted by a newer one) must not write back over
            # the current run's live state — it only owns `state` while it is still
            # the active orchestrator.
            def _mine() -> bool:
                return state.get("orch") is orch
            try:
                orch.run()
                if _mine():
                    state["status"] = "cancelled" if orch.cancelled else "done"
            except Exception as exc:  # a crashed run must not take the server down
                if _mine():
                    state["status"] = "error"
                    state["error"] = f"{exc.__class__.__name__}: {exc}"
            finally:
                if _mine():
                    state["finished"] = now_iso()

        t = threading.Thread(target=_work, daemon=True)
        state["thread"] = t
        t.start()

    def _stop_current(timeout: float = 12.0) -> bool:
        """Ask the in-flight run to stop and wait briefly for it to wind down.
        Returns True once no run is active."""
        orch = state.get("orch")
        if orch is not None:
            orch.cancel()
        t = state["thread"]
        if t is not None and t.is_alive():
            t.join(timeout=timeout)
        return not _running()

    def _load_checks() -> list[dict]:
        return load_checks(_CHECKS_FILE) if _CHECKS_FILE.is_file() else []

    # Auto-start a run at boot when the scope is already calibrated.
    if autostart and (config.scope.networks or config.scope.hosts or config.scope.binaries):
        _launch(config, _load_checks(), bb, scope_path=str(_SCOPE_FILE))

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        try:
            return _DASHBOARD.read_text(encoding="utf-8")
        except OSError:
            return "<h1>NightTrace</h1><p>Dashboard asset missing.</p>"

    @app.get("/healthz")
    def healthz() -> dict:
        cfg = state["config"]
        return {"ok": True, "engagement": cfg.engagement, "tier": cfg.tier,
                "run_status": state["status"], "running": _running()}


    @app.get("/targets")
    def targets() -> dict:
        bb = state["bb"]
        return {"assets": bb.list_assets(), "stats": bb.stats()}

    @app.get("/targets/{tid}/findings")
    def target_findings(tid: int):
        bb = state["bb"]
        asset = next((a for a in bb.list_assets() if a["id"] == tid), None)
        if not asset:
            return JSONResponse({"error": "target not found"}, status_code=404)
        return {"target": asset["host"], "port": asset.get("port"),
                "findings": bb.list_findings(asset_host=asset["host"])}

    @app.get("/findings")
    def findings(status: str | None = None):
        return {"findings": state["bb"].list_findings(status=status)}

    @app.get("/findings/{fid}")
    def finding(fid: int):
        f = state["bb"].get_finding(fid)
        if not f:
            return JSONResponse({"error": "finding not found"}, status_code=404)
        return f

    @app.get("/attack-path")
    def attack_path() -> dict:
        return attack_graph.search(state["bb"])

    @app.get("/hypotheses")
    def hypotheses() -> dict:
        return reporter.collect_hypotheses(state["bb"].list_events(0, 100000))

    @app.get("/events")
    def events(since: int = 0, limit: int = 500) -> dict:
        rows = state["bb"].list_events(since_id=since, limit=limit)
        return {"events": rows, "last_id": rows[-1]["id"] if rows else since}

    @app.get("/report")
    def report(format: str = "json"):
        bb, config = state["bb"], state["config"]
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
        return scoring.compute(state["bb"], ground_truth)

    # -- run control: scan the currently calibrated scope.yaml ----------------
    @app.post("/run")
    def run_engagement(payload: dict = Body(default={})):
        """Reload config/scope.yaml and scan it into a fresh blackboard. This is
        what the dashboard's Run button calls, so editing the scope and pressing
        Run re-points the engine with no restart and no demo."""
        with launch_lock:
            # Validate the new scope *before* stopping anything in flight.
            if not _SCOPE_FILE.is_file():
                return JSONResponse({"error": "no scope.yaml yet — calibrate the scope first at /scope-editor"},
                                    status_code=400)
            try:
                cfg = load_scope(_SCOPE_FILE)
            except Exception as exc:
                return JSONResponse({"error": f"scope.yaml is not runnable: {exc}"}, status_code=400)
            preempted = False
            if _running():  # a run is in flight — preempt it so Re-scan is never blocked
                preempted = True
                # Ask it to stop and give it a short grace period to wind down
                # cleanly. A scan of a *remote* host can have slow network tasks
                # still in flight that outlast the grace window — so we never block
                # the user on it: each run is fully isolated (its own blackboard,
                # orchestrator and scope guard), so the new run starts regardless
                # and the old, cancelled one finishes on its own in the background.
                _stop_current(timeout=8.0)
            _launch(cfg, _load_checks(), Blackboard(), scope_path=str(_SCOPE_FILE))
            return {"status": "running", "preempted": preempted,
                    "engagement": cfg.engagement, "tier": cfg.tier,
                    "targets": {"networks": cfg.scope.networks, "hosts": cfg.scope.hosts,
                                "urls": cfg.scope.urls, "binaries": cfg.scope.binaries}}

    @app.post("/run/stop")
    def run_stop() -> dict:
        """Abort the current run without starting a new one."""
        with launch_lock:
            if not _running():
                return {"status": state["status"], "running": False}
            _stop_current()
            return {"status": state["status"], "running": _running()}

    @app.get("/run/status")
    def run_status() -> dict:
        cfg = state["config"]
        return {"status": state["status"], "running": _running(),
                "started": state["started"], "finished": state["finished"],
                "error": state["error"], "scope_path": state["scope_path"],
                "engagement": cfg.engagement, "tier": cfg.tier,
                "stats": state["bb"].stats()}

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
        cfg = state["config"]
        if _SCOPE_FILE.is_file():
            try:
                return {"exists": True, "path": str(_SCOPE_FILE),
                        "scope": yaml.safe_load(_SCOPE_FILE.read_text(encoding="utf-8")) or {}}
            except Exception as exc:  # malformed file: let the UI show it
                return {"exists": True, "path": str(_SCOPE_FILE), "error": str(exc)}
        return {"exists": False, "path": str(_SCOPE_FILE), "scope": {
            "engagement": cfg.engagement, "tier": cfg.tier,
            "scope": {"networks": [], "hosts": [], "urls": [], "binaries": [], "exclude": [], "ports": []},
            "limits": {"max_runtime_minutes": cfg.limits.max_runtime_minutes,
                       "rate_limit_pps": cfg.limits.rate_limit_pps, "destructive": False},
            "flags": {"pattern": cfg.flag_pattern}}}

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
        urls = _clean(payload.get("urls"))
        for n in networks:
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError:
                errors.append(f"invalid network CIDR: {n}")
        for u in urls:
            try:
                parse_web_target(u)
            except ValueError as exc:
                errors.append(str(exc))

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

        if not (networks or hosts or binaries or urls):
            errors.append("scope is empty — add at least one URL, network, host, or binary")

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
            "scope": {"networks": networks, "hosts": hosts, "urls": urls, "binaries": binaries,
                      "exclude": exclude, "ports": ports},
            "limits": {"max_runtime_minutes": mrt, "rate_limit_pps": rpp, "destructive": False},
            "flags": {"pattern": state["config"].flag_pattern},
        }
        text = yaml.safe_dump(doc, sort_keys=False)
        _CONFIG.mkdir(parents=True, exist_ok=True)
        _SCOPE_FILE.write_text(text, encoding="utf-8")
        try:  # confirm the engine will accept what we just wrote
            load_scope(_SCOPE_FILE)
        except Exception as exc:
            return JSONResponse({"errors": [f"written but failed validation: {exc}"], "yaml": text},
                                status_code=400)
        return {"path": str(_SCOPE_FILE), "yaml": text,
                "run": "press Run on the dashboard, or: nighttrace run --scope config/scope.yaml --out reports"}

    @app.post("/network/scope")
    def network_scope(payload: dict = Body(default={})):
        payload = payload or {}
        ips = [str(x).strip() for x in payload.get("ips", []) if str(x).strip()]
        if not ips:
            return JSONResponse({"error": "select at least one host"}, status_code=400)
        _CONFIG.mkdir(parents=True, exist_ok=True)
        text = netdiscover.write_scope(
            _SCOPE_FILE, ips,
            cidr=payload.get("cidr"),
            engagement=payload.get("engagement") or "hackathon-engagement",
            tier=payload.get("tier") or "breach",
            exclude=payload.get("exclude") or [],
        )
        return {"path": str(_SCOPE_FILE), "yaml": text,
                "run": "press Run on the dashboard, or: nighttrace run --scope config/scope.yaml --out reports"}

    return app
