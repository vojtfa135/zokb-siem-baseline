#!/usr/bin/env python3
"""Validate cross-references in the ZoKB compliance baseline.

Checks performed:
  * higher-profile retention must be an integer >= 18 months;
  * every higher-profile mandatory event class has a coverage entry with at
    least one log source and one detection rule;
  * lower-profile detection rules must not require FLD-E;
  * every log source id referenced in mappings/coverage.yaml resolves to a file
    in logging/sources/ (catches typos / missing files);
  * every log source file is referenced at least once in coverage (no orphans);
  * source files reference only event-class and field ids that actually exist.

Dependencies: PyYAML only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_sources() -> tuple[dict[str, dict], list[str]]:
    """Return ({source_id: parsed_data}, errors) for logging/sources/*.yaml."""
    sources: dict[str, dict] = {}
    id_to_file: dict[str, Path] = {}
    errors: list[str] = []
    sources_dir = ROOT / "logging" / "sources"
    for src_path in sorted(sources_dir.glob("*.yaml")):
        data = load_yaml(src_path) or {}
        rel = src_path.relative_to(ROOT)
        sid = data.get("id")
        if not sid:
            errors.append(f"Source file {rel} is missing an 'id'.")
            continue
        if sid in id_to_file:
            errors.append(
                f"Duplicate source id '{sid}' in {rel} and "
                f"{id_to_file[sid].relative_to(ROOT)}."
            )
            continue
        id_to_file[sid] = src_path
        sources[sid] = data
    return sources, errors


def load_known_ids() -> tuple[set[str], set[str]]:
    """Return (event_class_ids, field_ids) declared in the logging baseline."""
    evt_ids: set[str] = set()
    for fname in ("event-classes.yaml", "event-classes-detection.yaml"):
        data = load_yaml(ROOT / "logging" / fname) or {}
        for ec in data.get("event_classes", []) or []:
            if ec.get("id"):
                evt_ids.add(ec["id"])
    fld_data = load_yaml(ROOT / "logging" / "required-fields.yaml") or {}
    fld_ids = {f["id"] for f in (fld_data.get("fields", []) or []) if f.get("id")}
    return evt_ids, fld_ids


def coverage_source_ids(coverage: dict) -> set[str]:
    """All log source ids referenced anywhere in the coverage matrix."""
    referenced: set[str] = set()
    for regime in (coverage.get("coverage", {}) or {}).values():
        for mapped in (regime.get("event_classes", {}) or {}).values():
            for sid in (mapped or {}).get("log_sources", []) or []:
                referenced.add(sid)
    return referenced


def collect_detection_rule_fields() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for rule_path in (ROOT / "detections").rglob("*.yml"):
        data = load_yaml(rule_path) or {}
        title = (data.get("title") or "").lower()
        rid = data.get("id", "")
        key = ""
        if "failed logons from same source" in title:
            key = "zokb-auth-failed-logons-bruteforce"
        elif "correlated brute-force" in title:
            key = "zokb-auth-failed-logons-correlation"
        elif "antimalware" in title:
            key = "zokb-malware-antimalware-detection"
        elif "perimeter blocked" in title:
            key = "zokb-net-perimeter-block"
        elif "removable media autorun" in title:
            key = "zokb-host-removable-media-autorun"
        if key:
            result[key] = data.get("zokb_required_fields", []) or []
        elif rid:
            result[rid] = data.get("zokb_required_fields", []) or []
    return result


def main() -> int:
    higher = load_yaml(ROOT / "profiles" / "higher.yaml") or {}
    lower = load_yaml(ROOT / "profiles" / "lower.yaml") or {}
    coverage = load_yaml(ROOT / "mappings" / "coverage.yaml") or {}

    errors: list[str] = []

    # --- retention -------------------------------------------------------
    higher_ret = higher.get("parameters", {}).get("retention_months")
    if not isinstance(higher_ret, int) or higher_ret < 18:
        errors.append("Higher profile retention_months must be an integer >= 18.")

    # --- higher mandatory event-class coverage ---------------------------
    higher_mandatory = higher.get("event_classes", {}).get("mandatory", []) or []
    higher_cov = (
        coverage.get("coverage", {}).get("higher", {}).get("event_classes", {}) or {}
    )
    for evt in higher_mandatory:
        mapped = higher_cov.get(evt)
        if not mapped:
            errors.append(f"Missing coverage entry for higher mandatory event class: {evt}")
            continue
        if not mapped.get("log_sources"):
            errors.append(f"Higher event class {evt} has no log source mapping.")
        if not mapped.get("detection_rules"):
            errors.append(f"Higher event class {evt} has no detection rule mapping.")

    # --- lower profile must not require FLD-E ----------------------------
    lower_rule_ids = set(lower.get("detection_rules", []) or [])
    rule_fields = collect_detection_rule_fields()
    for rule_id in lower_rule_ids:
        if "FLD-E" in rule_fields.get(rule_id, []):
            errors.append(
                f"Lower profile detection rule {rule_id} requires FLD-E, which is not allowed."
            )

    # --- log source <-> file linkage ------------------------------------
    sources, source_errors = load_sources()
    errors.extend(source_errors)
    evt_ids, fld_ids = load_known_ids()

    referenced = coverage_source_ids(coverage)
    defined = set(sources.keys())

    for sid in sorted(referenced - defined):
        errors.append(
            f"coverage.yaml references log source '{sid}' but no file in "
            f"logging/sources/ defines it."
        )
    for sid in sorted(defined - referenced):
        errors.append(
            f"Log source '{sid}' is defined in logging/sources/ but never "
            f"referenced in mappings/coverage.yaml (orphan)."
        )

    # --- source event-class / field references must exist ----------------
    for sid, data in sources.items():
        for evt in data.get("must_emit_event_classes", []) or []:
            if evt not in evt_ids:
                errors.append(f"Source {sid} references unknown event class '{evt}'.")
        for fld in data.get("must_emit_fields", []) or []:
            if fld not in fld_ids:
                errors.append(f"Source {sid} references unknown field '{fld}'.")

    if errors:
        print("Coverage validation FAILED:")
        for e in errors:
            print(f"- {e}")
        return 1

    print("Coverage validation PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
