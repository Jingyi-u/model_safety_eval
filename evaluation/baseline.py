from __future__ import annotations

import json
from pathlib import Path


def load_baseline(path: str | Path | None) -> dict | None:
    if not path:
        return None
    baseline_path = Path(path)
    if not baseline_path.exists():
        return None
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    if "summary" in data:
        return data
    if "attack_details" in data:
        return data
    return None


def compare_with_baseline(current_report: dict, baseline_report: dict | None) -> dict:
    if not baseline_report:
        return {}

    current = current_report.get("summary", {})
    baseline = baseline_report.get("summary", {})
    keys = [
        "overall_score",
        "breach_count",
        "chain_breach_count",
        "observed_tool_call_count",
        "unsafe_argument_count",
        "boundary_bypass_count",
        "data_exfiltration_count",
    ]

    deltas = {}
    for key in keys:
        current_value = _number(current.get(key, 0))
        baseline_value = _number(baseline.get(key, 0))
        deltas[key] = {
            "current": current_value,
            "baseline": baseline_value,
            "delta": round(current_value - baseline_value, 4),
        }

    current_findings = _finding_keys(current_report.get("attack_details", []))
    baseline_findings = _finding_keys(baseline_report.get("attack_details", []))
    new_findings = sorted(current_findings - baseline_findings)
    fixed_findings = sorted(baseline_findings - current_findings)

    regression = any(
        deltas[key]["delta"] > 0
        for key in ("breach_count", "chain_breach_count", "boundary_bypass_count", "data_exfiltration_count")
    ) or bool(new_findings)

    return {
        "baseline_name": baseline_report.get("meta", {}).get("name", ""),
        "current_name": current_report.get("meta", {}).get("name", ""),
        "regression": regression,
        "deltas": deltas,
        "new_findings": new_findings[:50],
        "fixed_findings": fixed_findings[:50],
    }


def _finding_keys(results: list[dict]) -> set[str]:
    keys = set()
    for result in results:
        level = result.get("judge_result", {}).get("level", 0)
        confirmed = result.get("verification", {}).get("confirmed", False)
        if level < 2 and not confirmed:
            continue
        keys.add("|".join([
            result.get("dimension", ""),
            result.get("technique_id", ""),
            result.get("intent", ""),
            result.get("metadata", {}).get("target_tool", ""),
            result.get("metadata", {}).get("attack_method", ""),
        ]))
    return keys


def _number(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
