"""Command-line interface.

    nighttrace run   --scope scope.yaml [--out reports/] [--ground-truth gt.yaml]
    nighttrace serve --scope scope.yaml [--host 127.0.0.1 --port 8000]
    nighttrace score --scope scope.yaml --ground-truth gt.yaml

`run` is the whole engagement in one command; `serve` also brings up the live
dashboard while the engine works; `score` grades the run against ground truth.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nighttrace import reporter, scoring
from nighttrace.blackboard import Blackboard
from nighttrace.config import Config, apply_urls, config_from_urls, load_checks, load_scope
from nighttrace.orchestrator import Orchestrator


DEFAULT_SCOPE = "config/scope.yaml"


def _load(args) -> tuple:
    urls = getattr(args, "url", None) or []
    if urls and not args.scope:
        # Bare --url: scan exactly the given website(s), nothing else.
        config = config_from_urls(urls)
    else:
        # No --url, or an explicit --scope to combine with: load the scope file
        # (the default when none was named) and fold any --url targets into it.
        config = load_scope(args.scope or DEFAULT_SCOPE)
        if urls:
            config = apply_urls(config, urls)
    checks = load_checks(args.checks) if args.checks and Path(args.checks).is_file() else []
    return config, checks


def _print_summary(report: dict) -> None:
    s = report.get("scope_safety") or {}
    st = report["stats"]
    print(f"\n  NightTrace - {report['engagement']} (tier {report['tier']}, x{report['score_multiplier']})")
    print(f"  duration {report.get('duration_seconds')}s | assets {st['assets']} | "
          f"confirmed {st['confirmed']} | refuted {st['refuted']} | "
          f"stray probes {s.get('stray_probe_attempts', 0)}")
    if report["confirmed_findings"]:
        print("\n  Confirmed findings:")
        for f in report["confirmed_findings"]:
            loc = f.get("asset_host") or ""
            if f.get("asset_port"):
                loc += f":{f['asset_port']}"
            print(f"    [{f['severity'].upper():<8}] {f['title']}  @ {loc}")
            evidence = f.get("evidence") or []
            if evidence:
                for item in evidence:
                    kind = item.get("kind", "evidence")
                    content = item.get("content", "")
                    print(f"      Evidence [{kind}]: {content}")
            else:
                print("      Evidence: none captured")
    for p in report["attack_paths"]:
        chain = " -> ".join([p["steps"][0]["from"]] + [x["to"] for x in p["steps"]])
        print(f"\n  Attack path ({p['goal']}): {chain}")


def cmd_run(args) -> int:
    config, checks = _load(args)
    orch = Orchestrator(config, checks)
    report = orch.run()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(reporter.render_markdown(report), encoding="utf-8")
    (out / "report.json").write_text(reporter.render_json(report), encoding="utf-8")
    (out / "report.html").write_text(reporter.render_html(report), encoding="utf-8")
    _print_summary(report)
    print(f"\n  Report written: {out/'report.md'} (+ .json, .html)")

    if args.ground_truth and Path(args.ground_truth).is_file():
        print("\n" + scoring.render(scoring.compute(orch.bb, args.ground_truth)))
    return 0


def cmd_score(args) -> int:
    if not args.ground_truth:
        print("error: score requires --ground-truth", file=sys.stderr)
        return 2
    config, checks = _load(args)
    orch = Orchestrator(config, checks)
    report = orch.run()
    _print_summary(report)
    print("\n" + scoring.render(scoring.compute(orch.bb, args.ground_truth)))
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from nighttrace.api import create_app
    bb = Blackboard()
    urls = getattr(args, "url", None) or []
    scope_path = args.scope or DEFAULT_SCOPE
    # Bring the dashboard up around the calibrated scope. If a runnable scope
    # already exists, auto-start the engagement; otherwise come up idle so the
    # scope can be calibrated from the UI and started with the Run button.
    if urls and not args.scope:  # bare --url: start straight from the website(s)
        config = config_from_urls(urls)
        autostart = True
        print(f"\n  starting from --url target(s): {', '.join(urls)} (tier {config.tier})")
    else:
        try:
            config = load_scope(scope_path)
            if urls:
                config = apply_urls(config, urls)
            autostart = True
            print(f"\n  scope loaded from {scope_path} — starting engagement '{config.engagement}' (tier {config.tier})")
        except (ValueError, FileNotFoundError) as exc:
            config = Config()
            autostart = False
            print(f"\n  no runnable scope at {scope_path} yet ({exc})")
            print(f"  calibrate it at http://{args.host}:{args.port}/scope-editor, then press Run")

    checks = load_checks(args.checks) if Path(args.checks).is_file() else []
    app = create_app(bb, config, checks=checks, autostart=autostart)
    print(f"  NightTrace live at http://{args.host}:{args.port}  (dashboard at /)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0




def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nighttrace", description="Autonomous multi-agent pentest engine (authorized, in-scope only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--scope", default=None,
                        help="scope file (YAML or JSON) [default: config/scope.yaml]")
        sp.add_argument("--url", action="append", metavar="URL",
                        help="website target, e.g. https://example.com (repeatable). "
                             "Alone, scans just the URL(s); with --scope, adds to that scope")
        sp.add_argument("--checks", default="config/checks.yaml", help="declarative checks file")
        sp.add_argument("--ground-truth", default=None, help="ground-truth file for self-scoring")

    r = sub.add_parser("run", help="run the full engagement once and write a report")
    common(r); r.add_argument("--out", default="reports", help="output directory")
    r.set_defaults(func=cmd_run)

    sc = sub.add_parser("score", help="run and grade against ground truth")
    common(sc); sc.set_defaults(func=cmd_score)

    sv = sub.add_parser("serve", help="run with the live API + dashboard")
    common(sv)
    sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
