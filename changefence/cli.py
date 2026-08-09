import argparse
import json
import sys
from .behavior import BehaviorError, compare_behavior
from .engine import compare
from .report import write_html
from .spec import SpecError, load_spec


def _render_path(path):
    return " -> ".join(path)


def _load_compare(base, candidate, fail_on):
    return compare(load_spec(base), load_spec(candidate), fail_on=fail_on)


def _print_structural(report):
    print("CHANGEFENCE")
    print(f"Baseline:  {report['base']}")
    print(f"Candidate: {report['candidate']}")
    print()
    print(f"Security gate: {report['status']}")
    s = report["summary"]
    print(f"Structural changes:       {s['structural_changes']}")
    print(f"New reachable capabilities: {s['new_capabilities']}")
    print(f"New security regressions: {s['new_security_regressions']}")

    if report["new_security_regressions"]:
        print("\nNEW SECURITY REGRESSIONS")
        for v in report["new_security_regressions"]:
            print(f"\n[{v['severity'].upper()}] {v['id']} — {v['description']}")
            print(f"New authority: {v['source_agent']} -> {v['capability']}")
            print(f"Path: {_render_path(v['path'])}")

    if report["new_capabilities"]:
        print("\nNEW CAPABILITY SURFACE")
        for item in report["new_capabilities"]:
            print(f"- [{item['severity']}] {item['source_agent']} -> {item['capability']}")


def _print_behavior(report):
    print("CHANGEFENCE BEHAVIORAL SECURITY DIFF")
    print(f"Security gate: {report['status']}")
    print(f"Scenarios: {report['summary']['scenarios']}")
    print(f"Regressions: {report['summary']['regressions']}")
    for row in report["regressions"]:
        print(f"- {row['scenario']}: {row['base']['pass_rate']:.0%} -> {row['candidate']['pass_rate']:.0%}")


def main():
    parser = argparse.ArgumentParser(prog="changefence", description="Security change control for AI agents")
    sub = parser.add_subparsers(dest="command", required=True)

    cmp_parser = sub.add_parser("compare", help="Compare baseline and candidate agent authority")
    cmp_parser.add_argument("base")
    cmp_parser.add_argument("candidate")
    cmp_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    cmp_parser.add_argument("--json", action="store_true", dest="as_json")

    beh_parser = sub.add_parser("behavior-diff", help="Compare adversarial test results between releases")
    beh_parser.add_argument("base")
    beh_parser.add_argument("candidate")
    beh_parser.add_argument("--threshold", type=float, default=0.20)
    beh_parser.add_argument("--json", action="store_true", dest="as_json")

    report_parser = sub.add_parser("report", help="Generate a shareable HTML security diff")
    report_parser.add_argument("base")
    report_parser.add_argument("candidate")
    report_parser.add_argument("--behavior-base")
    report_parser.add_argument("--behavior-candidate")
    report_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    report_parser.add_argument("--threshold", type=float, default=0.20)
    report_parser.add_argument("--out", default="changefence-report.html")

    args = parser.parse_args()

    try:
        if args.command == "compare":
            report = _load_compare(args.base, args.candidate, args.fail_on)
            print(json.dumps(report, indent=2)) if args.as_json else _print_structural(report)
            raise SystemExit(1 if report["status"] == "FAIL" else 0)

        if args.command == "behavior-diff":
            report = compare_behavior(args.base, args.candidate, threshold=args.threshold)
            print(json.dumps(report, indent=2)) if args.as_json else _print_behavior(report)
            raise SystemExit(1 if report["status"] == "FAIL" else 0)

        if args.command == "report":
            structural = _load_compare(args.base, args.candidate, args.fail_on)
            behavior = None
            if bool(args.behavior_base) != bool(args.behavior_candidate):
                parser.error("--behavior-base and --behavior-candidate must be provided together")
            if args.behavior_base:
                behavior = compare_behavior(args.behavior_base, args.behavior_candidate, threshold=args.threshold)
            path = write_html(args.out, structural, behavior)
            print(f"ChangeFence report written to {path}")
            combined_fail = structural["status"] == "FAIL" or (behavior and behavior["status"] == "FAIL")
            raise SystemExit(1 if combined_fail else 0)
    except (SpecError, BehaviorError) as exc:
        print(f"ChangeFence error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
