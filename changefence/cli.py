import argparse
import json
import sys
from pathlib import Path

from .approvals import (
    ApprovalLeaseError,
    issue_approval_lease,
    secret_from_env,
    validate_approval_lease,
)
from .behavior import BehaviorError, compare_behavior
from .descriptors import DescriptorError, build_descriptor_context
from .engine import compare
from .hypotheses import HypothesisError, generate_attack_hypotheses
from .impact import build_impact_report, write_promptfoo_tests
from .ledger import LedgerError, append_event, verify_ledger
from .policy import build_policy_plan
from .report import write_html
from .runtime import RuntimeDecisionError, authorize_action, decide_action
from .semantic import SemanticError
from .spec import SpecError, load_spec


def _render_path(path):
    return " -> ".join(path)


def _load(path, policy=None):
    return load_spec(path, policy_path=policy)


def _load_compare(base, candidate, fail_on, policy=None):
    return compare(_load(base, policy), _load(candidate, policy), fail_on=fail_on)


def _read_optional(path):
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8")


def _read_json_file(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ApprovalLeaseError(f"Expected a JSON object in {path}.")
    return value


def _json_object(value, *, label):
    if not value:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ApprovalLeaseError(f"{label} must be a JSON object.")
    return parsed


def _print_policy_authority(authority):
    if not authority:
        return
    print(
        f"Policy:     {authority['name']} v{authority['version']} "
        f"· owner={authority['owner']} · sha256={authority['digest'][:12]}…"
    )


def _print_structural(report):
    print("CHANGEFENCE")
    print(f"Baseline:  {report['base']}")
    print(f"Candidate: {report['candidate']}")
    print()
    print(f"Security gate: {report['status']}")
    s = report["summary"]
    print(f"Structural changes: {s['structural_changes']}")
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


def _print_impact(report):
    print("CHANGEFENCE IMPACT")
    print(f"Baseline:  {report['base']}")
    print(f"Candidate: {report['candidate']}")
    _print_policy_authority(report.get("policy_authority"))
    print(f"Decision:  {report['decision']}")
    print(f"Reason:    {report['decision_reason']}")
    s = report["summary"]
    print()
    print(f"Structural changes:         {s['structural_changes']}")
    print(f"PROVEN new capabilities:   {s['proven_new_capabilities']}")
    print(f"HYPOTHESIZED capabilities: {s['inferred_new_capabilities']}")
    print(f"Semantic risks:             {s['semantic_risks']}")
    print(f"Targeted tests generated:   {s['targeted_tests']}")
    if report["proven_findings"]:
        print("\nPROVEN CAPABILITY DELTA")
        for item in report["proven_findings"]:
            print(f"- [{item['severity'].upper()}] {item['source_agent']} -> {item['capability']}")
            print(f"  path: {_render_path(item['path'])}")
    if report["inferred_findings"]:
        print("\nHYPOTHESIZED CAPABILITY DELTA")
        for item in report["inferred_findings"]:
            print(f"- [{item['severity'].upper()}] {item['source_agent']} -> {item['capability']}")
            print("  requires mapping review")
    semantic = report.get("semantic") or {}
    if semantic.get("semantic_risks"):
        print("\nSEMANTIC RISKS — REQUIRE RUNTIME VERIFICATION")
        for risk in semantic["semantic_risks"]:
            print(f"- [{risk['severity'].upper()}] {risk['agent']} / {risk['affected_capability']}")
            print(f"  {risk['rationale']}")
    if report["targeted_attacks"]:
        print("\nCHANGE-DIRECTED TESTS")
        for attack in report["targeted_attacks"]:
            print(f"- {attack['id']} {attack['title']} -> {attack['target_capability']}")


def _print_runtime(decision):
    print("CHANGEFENCE RUNTIME")
    print(f"Decision:   {decision['decision']}")
    print(f"Origin:     {decision['origin_agent']}")
    print(f"Capability: {decision['capability']}")
    _print_policy_authority(decision.get("policy_authority"))
    print(f"Reason:     {decision['reason']}")
    if decision.get("review"):
        review = decision["review"]
        print(f"Reviewer:   {review['approver']}")
        print(f"Approval:   {review['max_uses']} use(s), expires in {review['expires_minutes']} minutes")
    if decision.get("authorization"):
        auth = decision["authorization"]
        print(f"Authorized: {auth['approved_by']} via {auth['rule_id']}")
        print(f"Lease:      {auth['lease_id']} · remaining uses {auth['uses_remaining']}")
    if decision.get("lease_validation") and not decision["lease_validation"].get("valid"):
        print(f"Lease:      INVALID · {decision['lease_validation']['reason']}")


def _add_policy_arg(parser):
    parser.add_argument(
        "--policy",
        help=(
            "Security-owned policy registry YAML. When supplied, its invariants/reviews "
            "replace any rules embedded in developer-controlled agent specs."
        ),
    )


def main():
    parser = argparse.ArgumentParser(prog="changefence", description="AI security from change impact to runtime evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    cmp_parser = sub.add_parser("compare", help="Compare baseline and candidate agent authority")
    cmp_parser.add_argument("base")
    cmp_parser.add_argument("candidate")
    cmp_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    _add_policy_arg(cmp_parser)
    cmp_parser.add_argument("--json", action="store_true", dest="as_json")

    impact_parser = sub.add_parser("impact", help="Translate an agent change into security consequences")
    impact_parser.add_argument("base")
    impact_parser.add_argument("candidate")
    impact_parser.add_argument("--diff", help="Unified diff or PR patch file for semantic analysis")
    impact_parser.add_argument("--context", help="Optional repository/tool/API context file")
    impact_parser.add_argument("--descriptor", action="append", default=[], help="OpenAPI or MCP-style JSON/YAML descriptor; repeat as needed")
    impact_parser.add_argument("--llm", action="store_true", help="Use local Ollama for semantic compilation and targeted test generation")
    impact_parser.add_argument("--model", default="gemma3")
    impact_parser.add_argument("--url", default="http://localhost:11434")
    impact_parser.add_argument("--timeout", type=int, default=120)
    impact_parser.add_argument("--attacks", type=int, default=6)
    impact_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    impact_parser.add_argument("--promptfoo-out", help="Write generated targeted tests as Promptfoo external-tests YAML")
    _add_policy_arg(impact_parser)
    impact_parser.add_argument("--json", action="store_true", dest="as_json")

    runtime_parser = sub.add_parser("runtime", help="Evaluate a security-relevant action before execution")
    runtime_parser.add_argument("spec")
    runtime_parser.add_argument("origin")
    runtime_parser.add_argument("capability")
    runtime_parser.add_argument("--executor")
    _add_policy_arg(runtime_parser)
    runtime_parser.add_argument("--lease", help="Signed approval lease JSON to consume when the action requires REVIEW")
    runtime_parser.add_argument("--usage-store", default=".changefence/approval-usage.json", help="Signed replay/usage state for approval leases")
    runtime_parser.add_argument("--secret-env", default="CHANGEFENCE_APPROVAL_SECRET", help="Environment variable containing the approval signing secret")
    runtime_parser.add_argument("--ledger", help="Optional ChangeFence Ledger to record a consumed approval")
    runtime_parser.add_argument("--json", action="store_true", dest="as_json")

    approve_parser = sub.add_parser("approve", help="Issue a signed short-lived lease after a trusted host authenticates a reviewer")
    approve_parser.add_argument("spec")
    approve_parser.add_argument("origin")
    approve_parser.add_argument("capability")
    approve_parser.add_argument("--executor")
    _add_policy_arg(approve_parser)
    approve_parser.add_argument("--approved-by", required=True, help="Authenticated human identity supplied by the trusted host")
    approve_parser.add_argument("--approver-group", required=True, help="Authenticated reviewer group/role supplied by the trusted host")
    approve_parser.add_argument("--context", help="Optional JSON object, for example '{\"pr\":284,\"ticket\":\"SEC-91\"}'")
    approve_parser.add_argument("--secret-env", default="CHANGEFENCE_APPROVAL_SECRET")
    approve_parser.add_argument("--out", default="changefence-approval.json")
    approve_parser.add_argument("--ledger", help="Optional ChangeFence Ledger to record lease issuance")

    approval_verify = sub.add_parser("approval-verify", help="Validate an approval lease without consuming it")
    approval_verify.add_argument("spec")
    approval_verify.add_argument("origin")
    approval_verify.add_argument("capability")
    approval_verify.add_argument("lease")
    approval_verify.add_argument("--executor")
    _add_policy_arg(approval_verify)
    approval_verify.add_argument("--usage-store", default=".changefence/approval-usage.json")
    approval_verify.add_argument("--secret-env", default="CHANGEFENCE_APPROVAL_SECRET")
    approval_verify.add_argument("--json", action="store_true", dest="as_json")

    policy_parser = sub.add_parser("policy", help="Generate reviewable control recommendations from an Impact report")
    policy_parser.add_argument("base")
    policy_parser.add_argument("candidate")
    policy_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    _add_policy_arg(policy_parser)
    policy_parser.add_argument("--json", action="store_true", dest="as_json")

    ledger_append = sub.add_parser("ledger-append", help="Append a security event to the tamper-evident ledger")
    ledger_append.add_argument("ledger")
    ledger_append.add_argument("event_type")
    ledger_append.add_argument("payload", help="JSON object containing the evidence payload")

    ledger_verify = sub.add_parser("ledger-verify", help="Verify the tamper-evident evidence ledger")
    ledger_verify.add_argument("ledger")
    ledger_verify.add_argument("--json", action="store_true", dest="as_json")

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
    _add_policy_arg(report_parser)

    hyp_parser = sub.add_parser("hypothesize", help="Generate local-LLM attack hypotheses and verify them deterministically")
    hyp_parser.add_argument("base")
    hyp_parser.add_argument("candidate")
    hyp_parser.add_argument("--model", default="gemma3")
    hyp_parser.add_argument("--url", default="http://localhost:11434")
    hyp_parser.add_argument("--count", type=int, default=6)
    hyp_parser.add_argument("--timeout", type=int, default=120)
    _add_policy_arg(hyp_parser)
    hyp_parser.add_argument("--json", action="store_true", dest="as_json")

    args = parser.parse_args()
    try:
        if args.command == "compare":
            report = _load_compare(args.base, args.candidate, args.fail_on, args.policy)
            print(json.dumps(report, indent=2)) if args.as_json else _print_structural(report)
            raise SystemExit(1 if report["status"] == "FAIL" else 0)

        if args.command == "impact":
            base = _load(args.base, args.policy)
            candidate = _load(args.candidate, args.policy)
            report = build_impact_report(
                base,
                candidate,
                diff_text=_read_optional(args.diff),
                repository_context="\n".join(x for x in [_read_optional(args.context), build_descriptor_context(args.descriptor)] if x),
                fail_on=args.fail_on,
                use_llm=args.llm,
                model=args.model,
                base_url=args.url,
                timeout=args.timeout,
                attack_count=args.attacks,
            )
            if args.promptfoo_out:
                path = write_promptfoo_tests(args.promptfoo_out, report["targeted_attacks"])
                report["promptfoo_tests_file"] = str(path)
            print(json.dumps(report, indent=2)) if args.as_json else _print_impact(report)
            raise SystemExit(1 if report["decision"] == "BLOCK" else 0)

        if args.command == "runtime":
            spec = _load(args.spec, args.policy)
            lease = _read_json_file(args.lease) if args.lease else None
            secret = secret_from_env(args.secret_env) if lease else None
            decision = authorize_action(
                spec,
                origin_agent=args.origin,
                executor_agent=args.executor,
                capability=args.capability,
                approval_lease=lease,
                approval_secret=secret,
                usage_path=args.usage_store if lease else None,
                consume=True,
            )
            if args.ledger and decision.get("authorization"):
                append_event(
                    args.ledger,
                    event_type="approval_lease_consumed",
                    payload={
                        "origin_agent": decision["origin_agent"],
                        "executor_agent": decision.get("executor_agent"),
                        "capability": decision["capability"],
                        "policy_authority": decision.get("policy_authority"),
                        "authorization": decision["authorization"],
                    },
                )
            print(json.dumps(decision, indent=2)) if args.as_json else _print_runtime(decision)
            raise SystemExit(1 if decision["decision"] == "BLOCK" else 3 if decision["decision"] == "REVIEW" else 0)

        if args.command == "approve":
            spec = _load(args.spec, args.policy)
            decision = decide_action(
                spec,
                origin_agent=args.origin,
                executor_agent=args.executor,
                capability=args.capability,
            )
            secret = secret_from_env(args.secret_env)
            lease = issue_approval_lease(
                spec,
                decision,
                approved_by=args.approved_by,
                approver_group=args.approver_group,
                secret=secret,
                context=_json_object(args.context, label="Approval context"),
            )
            Path(args.out).write_text(json.dumps(lease, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if args.ledger:
                append_event(
                    args.ledger,
                    event_type="approval_lease_issued",
                    payload={key: value for key, value in lease.items() if key != "signature"},
                )
            print("CHANGEFENCE APPROVAL")
            print(f"Lease:       {lease['lease_id']}")
            print(f"Approved by: {lease['approved_by']}")
            print(f"Scope:       {lease['origin_agent']} -> {lease['capability']}")
            print(f"Expires:     {lease['expires_at']}")
            print(f"Max uses:    {lease['max_uses']}")
            print(f"Written:     {args.out}")
            raise SystemExit(0)

        if args.command == "approval-verify":
            spec = _load(args.spec, args.policy)
            decision = decide_action(
                spec,
                origin_agent=args.origin,
                executor_agent=args.executor,
                capability=args.capability,
            )
            result = validate_approval_lease(
                spec,
                decision,
                _read_json_file(args.lease),
                secret=secret_from_env(args.secret_env),
                usage_path=args.usage_store,
            )
            print(json.dumps(result, indent=2)) if args.as_json else print(
                f"CHANGEFENCE APPROVAL: {'VALID' if result['valid'] else 'INVALID'} · {result['reason']}"
            )
            raise SystemExit(0 if result["valid"] else 1)

        if args.command == "policy":
            report = build_impact_report(
                _load(args.base, args.policy),
                _load(args.candidate, args.policy),
                fail_on=args.fail_on,
            )
            plan = build_policy_plan(report)
            if args.as_json:
                print(json.dumps(plan, indent=2))
            else:
                print("CHANGEFENCE POLICY")
                _print_policy_authority(report.get("policy_authority"))
                print(f"Recommendations: {plan['summary']['recommendations']}")
                for item in plan["recommendations"]:
                    print(f"- [{item['severity'].upper()}] {item['intent']}")
                    print(f"  invariant: {item['triggered_by_invariant']}")
                    print("  status: REVIEW_REQUIRED")
            raise SystemExit(0)

        if args.command == "ledger-append":
            payload = json.loads(args.payload)
            if not isinstance(payload, dict):
                raise LedgerError("Ledger payload must be a JSON object.")
            record = append_event(args.ledger, event_type=args.event_type, payload=payload)
            print(json.dumps(record, indent=2))
            raise SystemExit(0)

        if args.command == "ledger-verify":
            result = verify_ledger(args.ledger)
            print(json.dumps(result, indent=2)) if args.as_json else print(
                f"CHANGEFENCE LEDGER: {'VALID' if result['valid'] else 'INVALID'} · records={result['records']}"
            )
            raise SystemExit(0 if result["valid"] else 1)

        if args.command == "behavior-diff":
            report = compare_behavior(args.base, args.candidate, threshold=args.threshold)
            print(json.dumps(report, indent=2)) if args.as_json else _print_behavior(report)
            raise SystemExit(1 if report["status"] == "FAIL" else 0)

        if args.command == "hypothesize":
            base = _load(args.base, args.policy)
            candidate = _load(args.candidate, args.policy)
            report = generate_attack_hypotheses(base, candidate, model=args.model, count=args.count, base_url=args.url, timeout=args.timeout)
            if args.as_json:
                print(json.dumps(report, indent=2))
            else:
                print("CHANGEFENCE PROBE · LOCAL ATTACK HYPOTHESES")
                print(f"Model: {report['model']}")
                print(f"Generated: {report['summary']['generated']}")
                print(f"Verified new: {report['summary']['verified_new']}")
                print(f"Unreachable: {report['summary']['unreachable']}")
                for h in report["hypotheses"]:
                    print(f"\n[{h['verification']}] {h['id']} — {h['title']}")
                    print(f"Check: {h['source_agent']} -> {h['target_capability']}")
                    print(f"Hypothesis: {h['rationale']}")
                    if h["evidence_path"]:
                        print(f"Verified path: {_render_path(h['evidence_path'])}")
            raise SystemExit(0)

        if args.command == "report":
            structural = _load_compare(args.base, args.candidate, args.fail_on, args.policy)
            behavior = None
            if bool(args.behavior_base) != bool(args.behavior_candidate):
                parser.error("--behavior-base and --behavior-candidate must be provided together")
            if args.behavior_base:
                behavior = compare_behavior(args.behavior_base, args.behavior_candidate, threshold=args.threshold)
            path = write_html(args.out, structural, behavior)
            print(f"ChangeFence report written to {path}")
            combined_fail = structural["status"] == "FAIL" or (behavior and behavior["status"] == "FAIL")
            raise SystemExit(1 if combined_fail else 0)

    except (
        SpecError,
        BehaviorError,
        HypothesisError,
        SemanticError,
        DescriptorError,
        RuntimeDecisionError,
        ApprovalLeaseError,
        LedgerError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(f"ChangeFence error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
