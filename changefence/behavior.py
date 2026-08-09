import json
from collections import defaultdict
from pathlib import Path


class BehaviorError(ValueError):
    pass


def _load(path: str | Path) -> dict:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BehaviorError(f"Behavior run file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BehaviorError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise BehaviorError("Behavior file must contain a top-level 'runs' list.")
    return data


def _aggregate(data: dict) -> dict:
    grouped = defaultdict(list)
    for run in data["runs"]:
        if "scenario" not in run or "passed" not in run:
            raise BehaviorError("Each behavior run needs 'scenario' and boolean 'passed'.")
        grouped[str(run["scenario"])].append(bool(run["passed"]))

    result = {}
    for scenario, values in grouped.items():
        passes = sum(values)
        trials = len(values)
        result[scenario] = {
            "trials": trials,
            "passes": passes,
            "failures": trials - passes,
            "pass_rate": passes / trials if trials else 0.0,
        }
    return result


def compare_behavior(base_path: str | Path, candidate_path: str | Path, threshold: float = 0.20) -> dict:
    if not 0 <= threshold <= 1:
        raise BehaviorError("Threshold must be between 0 and 1.")
    base_raw, cand_raw = _load(base_path), _load(candidate_path)
    base, cand = _aggregate(base_raw), _aggregate(cand_raw)
    scenarios = sorted(set(base) | set(cand))

    rows = []
    regressions = []
    improvements = []
    for scenario in scenarios:
        b = base.get(scenario, {"trials": 0, "passes": 0, "failures": 0, "pass_rate": 0.0})
        c = cand.get(scenario, {"trials": 0, "passes": 0, "failures": 0, "pass_rate": 0.0})
        delta = c["pass_rate"] - b["pass_rate"]
        row = {
            "scenario": scenario,
            "base": b,
            "candidate": c,
            "pass_rate_delta": delta,
            "regression": delta <= -threshold,
            "improvement": delta >= threshold,
        }
        rows.append(row)
        if row["regression"]:
            regressions.append(row)
        if row["improvement"]:
            improvements.append(row)

    return {
        "status": "FAIL" if regressions else "PASS",
        "threshold": threshold,
        "base": base_raw.get("system", Path(base_path).stem),
        "candidate": cand_raw.get("system", Path(candidate_path).stem),
        "scenarios": rows,
        "regressions": regressions,
        "improvements": improvements,
        "summary": {
            "scenarios": len(rows),
            "regressions": len(regressions),
            "improvements": len(improvements),
        },
    }
