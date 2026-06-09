#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def collect_detection_rule_fields() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for rule_path in (ROOT / "detections").rglob("*.yml"):
        data = load_yaml(rule_path)
        title = data.get("title", "")
        rid = data.get("id", "")
        key = ""
        if "failed logons from same source" in title.lower():
            key = "zokb-auth-failed-logons-bruteforce"
        elif "correlated brute-force" in title.lower():
            key = "zokb-auth-failed-logons-correlation"
        elif "antimalware" in title.lower():
            key = "zokb-malware-antimalware-detection"
        elif "perimeter blocked" in title.lower():
            key = "zokb-net-perimeter-block"
        elif "removable media autorun" in title.lower():
            key = "zokb-host-removable-media-autorun"
        if key:
            result[key] = data.get("zokb_required_fields", [])
        elif rid:
            result[rid] = data.get("zokb_required_fields", [])
    return result


def main() -> int:
    higher = load_yaml(ROOT / "profiles" / "higher.yaml")
    lower = load_yaml(ROOT / "profiles" / "lower.yaml")
    coverage = load_yaml(ROOT / "mappings" / "coverage.yaml")

    errors: list[str] = []

    higher_ret = higher.get("parameters", {}).get("retention_months")
    if not isinstance(higher_ret, int) or higher_ret < 18:
        errors.append("Higher profile retention_months must be an integer >= 18.")

    higher_mandatory = higher.get("event_classes", {}).get("mandatory", [])
    higher_cov = coverage.get("coverage", {}).get("higher", {}).get("event_classes", {})
    for evt in higher_mandatory:
        mapped = higher_cov.get(evt)
        if not mapped:
            errors.append(f"Missing coverage entry for higher mandatory event class: {evt}")
            continue
        if not mapped.get("log_sources"):
            errors.append(f"Higher event class {evt} has no log source mapping.")
        if not mapped.get("detection_rules"):
            errors.append(f"Higher event class {evt} has no detection rule mapping.")

    lower_rule_ids = set(lower.get("detection_rules", []))
    rule_fields = collect_detection_rule_fields()
    for rule_id in lower_rule_ids:
        fields = rule_fields.get(rule_id, [])
        if "FLD-E" in fields:
            errors.append(f"Lower profile detection rule {rule_id} requires FLD-E, which is not allowed.")

    if errors:
        print("Coverage validation FAILED:")
        for e in errors:
            print(f"- {e}")
        return 1

    print("Coverage validation PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
