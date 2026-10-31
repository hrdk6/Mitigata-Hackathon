#!/usr/bin/env python
"""One-command, self-contained demo.

Starts the intentionally-vulnerable demo lab on localhost, generates the sample
binary, runs the full NightTrace engine against them, writes a report, and
self-scores against the planted ground truth. With --serve it instead brings up
the live dashboard + API while the engine works.

    python run_demo.py            # run once, print report + score
    python run_demo.py --serve    # live dashboard at http://127.0.0.1:8000/
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from nighttrace import reporter, scoring            # noqa: E402
from nighttrace.config import load_checks, load_scope  # noqa: E402
from nighttrace.orchestrator import Orchestrator     # noqa: E402
from targets import demo_lab, make_sample_binary     # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the self-contained NightTrace demo (localhost only).")
    ap.add_argument("--serve", action="store_true", help="keep the live dashboard + API running")
    ap.add_argument("--lab-port", type=int, default=8008)
    ap.add_argument("--api-port", type=int, default=8000)
    args = ap.parse_args()

    make_sample_binary.make(ROOT / "targets" / "bin" / "auth_service")
    httpd, _ = demo_lab.start("127.0.0.1", args.lab_port)
    print(f"[demo] NightLab target up on http://127.0.0.1:{args.lab_port}")
    time.sleep(0.3)

    config = load_scope(ROOT / "config" / "scope.demo.yaml")
    checks = load_checks(ROOT / "config" / "checks.yaml")

    if args.serve:
        import threading

        import uvicorn

        from nighttrace.api import create_app
        from nighttrace.blackboard import Blackboard
        bb = Blackboard()
        orch = Orchestrator(config, checks, blackboard=bb)
        threading.Thread(target=orch.run, daemon=True).start()
        print(f"[demo] live dashboard: http://127.0.0.1:{args.api_port}/")
        uvicorn.run(create_app(bb, config), host="127.0.0.1", port=args.api_port, log_level="warning")
        return 0

    orch = Orchestrator(config, checks)
    report = orch.run()

    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / "report.md").write_text(reporter.render_markdown(report), encoding="utf-8")
    (out / "report.json").write_text(reporter.render_json(report), encoding="utf-8")
    (out / "report.html").write_text(reporter.render_html(report), encoding="utf-8")

    from nighttrace.cli import _print_summary
    _print_summary(report)
    print(f"\n[demo] report -> {out / 'report.md'}  (+ .json, .html)")
    print("\n" + scoring.render(scoring.compute(orch.bb, ROOT / "targets" / "ground_truth.yaml")))
    httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
