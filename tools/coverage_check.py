#!/usr/bin/env python3
"""Validate cross-references in the ZoKB compliance baseline.

Checks performed (errors):
  * higher-profile retention must be an integer >= 18 months;
  * every higher-profile mandatory event class has a coverage entry with at
    least one log source and one detection rule;
  * lower-profile detection rules must not require FLD-E;
  * every log source id referenced in mappings/coverage.yaml resolves to a file
    in logging/sources/ (catches typos / missing files);
  * every log source file is referenced at least once in coverage (no orphans);
  * source files reference only event-class and field ids that actually exist;
  * every detection rule file declares a unique `zokb_rule_id` and a
    `modified:` date;
  * every detection rule id referenced in mappings/coverage.yaml or in a
    profile resolves to a rule file (prevents phantom mappings);
  * every correlation-rule leg resolves to a known rule `id`;
  * every detection rule is referenced by the coverage matrix or by a
    correlation rule (no orphan rules).

  * technology mapping files (logging/technologies/*.yaml, optional layer):
    unique `TECH-*` ids matching filename/org conventions, references to
    known `SRC-*` / `EVT-*` ids only, and per-block event classes that are a
    subset of the referenced source's `must_emit_event_classes` (never the
    union across blocks).

Checks performed (warnings, non-blocking):
  * semantic fit: for each coverage entry, at least one mapped rule's
    `event.category` / `event.type` selections overlap the event class's ECS
    mapping (catches rules that structurally cannot match a class's events).
  * technology mapping completeness: (source, event-class) pairs with no
    mapping in any logging/technologies/*.yaml file. This layer is entirely
    optional -- gaps are never a hard failure.

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


def load_technologies() -> tuple[dict[str, dict], list[str]]:
    """Return ({tech_id: parsed_data}, errors) for logging/technologies/*.yaml.

    This layer is optional and non-normative: an empty directory is valid.
    Any file that does exist must be internally consistent.
    """
    technologies: dict[str, dict] = {}
    id_to_file: dict[str, Path] = {}
    errors: list[str] = []
    tech_dir = ROOT / "logging" / "technologies"
    if not tech_dir.is_dir():
        return technologies, errors
    for tech_path in sorted(tech_dir.glob("*.yaml")):
        data = load_yaml(tech_path) or {}
        rel = tech_path.relative_to(ROOT)
        tid = data.get("id")
        if not tid:
            errors.append(f"Technology file {rel} is missing an 'id'.")
            continue
        if tid in id_to_file:
            errors.append(
                f"Duplicate technology id '{tid}' in {rel} and "
                f"{id_to_file[tid].relative_to(ROOT)}."
            )
            continue

        # Filename <-> id <-> org convention: TECH-[<ORG>-]<VENDOR>-<PRODUCT>
        # <=> filename {org-}{vendor}-{product}.yaml (kebab-case).
        stem = tech_path.stem  # e.g. 'org-fortigate' or 'windows-security'
        org = data.get("org")
        expected_id = f"TECH-{stem.upper()}"
        if tid != expected_id:
            errors.append(
                f"Technology {rel}: id '{tid}' does not match filename-derived "
                f"id '{expected_id}' (filename must be {{org-}}{{vendor}}-{{product}}.yaml "
                f"kebab-case matching TECH-[<ORG>-]<VENDOR>-<PRODUCT>)."
            )
        if org:
            org_slug = str(org).lower().replace("_", "-")
            if not stem.lower().startswith(org_slug + "-"):
                errors.append(
                    f"Technology {rel}: declares org '{org}' but filename does not "
                    f"start with '{org_slug}-'."
                )
            if not tid.startswith(f"TECH-{org.upper()}-"):
                errors.append(
                    f"Technology {rel}: declares org '{org}' but id '{tid}' does not "
                    f"start with 'TECH-{org.upper()}-'."
                )

        id_to_file[tid] = tech_path
        technologies[tid] = data
    return technologies, errors


def load_detection_rules() -> tuple[dict[str, dict], list[str]]:
    """Return ({zokb_rule_id: {'path', 'data'}}, errors) for detections/**/*.yml."""
    rules: dict[str, dict] = {}
    errors: list[str] = []
    for rule_path in sorted((ROOT / "detections").rglob("*.yml")):
        data = load_yaml(rule_path) or {}
        rel = rule_path.relative_to(ROOT)
        rid = data.get("zokb_rule_id")
        if not rid:
            errors.append(f"Detection rule {rel} is missing 'zokb_rule_id'.")
            continue
        if rid in rules:
            errors.append(
                f"Duplicate zokb_rule_id '{rid}' in {rel} and "
                f"{rules[rid]['path'].relative_to(ROOT)}."
            )
            continue
        if not data.get("modified"):
            errors.append(
                f"Detection rule '{rid}' ({rel}) is missing a 'modified:' date."
            )
        rules[rid] = {"path": rule_path, "data": data}
    return rules, errors


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


def load_event_class_ecs() -> dict[str, dict]:
    """Return {event_class_id: ecs_mapping} from both class definition files."""
    defs: dict[str, dict] = {}
    for fname in ("event-classes.yaml", "event-classes-detection.yaml"):
        data = load_yaml(ROOT / "logging" / fname) or {}
        for ec in data.get("event_classes", []) or []:
            if ec.get("id"):
                defs[ec["id"]] = ec.get("ecs", {}) or {}
    return defs


def coverage_source_ids(coverage: dict) -> set[str]:
    """All log source ids referenced anywhere in the coverage matrix."""
    referenced: set[str] = set()
    for regime in (coverage.get("coverage", {}) or {}).values():
        for mapped in (regime.get("event_classes", {}) or {}).values():
            for sid in (mapped or {}).get("log_sources", []) or []:
                referenced.add(sid)
    return referenced


def coverage_rule_ids(coverage: dict) -> set[str]:
    """All detection rule ids referenced anywhere in the coverage matrix."""
    referenced: set[str] = set()
    for regime in (coverage.get("coverage", {}) or {}).values():
        for mapped in (regime.get("event_classes", {}) or {}).values():
            for rid in (mapped or {}).get("detection_rules", []) or []:
                referenced.add(rid)
    return referenced


def selection_values(detection: dict, key: str) -> set[str]:
    """Collect values bound to `key` (ignoring |modifiers) across selections."""
    values: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                base = str(k).split("|")[0]
                if base == key:
                    vals = v if isinstance(v, list) else [v]
                    values.update(str(x) for x in vals)
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(detection)
    return values


def intersection(a: set, b: list) -> set:
    return a & {str(x) for x in (b or [])}


def validate_controls_coverage() -> list[str]:
    """Validate mappings/controls-coverage.yaml structure and artifacts."""
    path = ROOT / "mappings" / "controls-coverage.yaml"
    if not path.exists():
        return ["mappings/controls-coverage.yaml is missing."]
    data = load_yaml(path) or {}
    errors: list[str] = []
    statuses = {"implemented", "partial", "not-represented"}
    seen: set[str] = set()
    for ctrl in data.get("controls", []) or []:
        cid = ctrl.get("id") or "<missing>"
        if not ctrl.get("id") or not str(cid).startswith(("v409-", "v410-")):
            errors.append(f"Control entry has invalid id: {cid}")
        if cid in seen:
            errors.append(f"Duplicate control id in matrix: {cid}")
        seen.add(cid)
        if ctrl.get("status") not in statuses:
            errors.append(
                f"Control {cid} has invalid status '{ctrl.get('status')}' "
                f"(allowed: {sorted(statuses)})."
            )
        if not ctrl.get("owner"):
            errors.append(f"Control {cid} has no owner.")
        for artifact in ctrl.get("artifacts", []) or []:
            if not (ROOT / str(artifact)).exists():
                errors.append(f"Control {cid} references missing artifact: {artifact}")
    return errors


def main() -> int:
    higher = load_yaml(ROOT / "profiles" / "higher.yaml") or {}
    lower = load_yaml(ROOT / "profiles" / "lower.yaml") or {}
    coverage = load_yaml(ROOT / "mappings" / "coverage.yaml") or {}

    errors: list[str] = []
    warnings: list[str] = []

    # --- §23 / §9.1.d-e process-control matrix ---------------------------
    errors.extend(validate_controls_coverage())

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

    # --- detection rule inventory & reference resolution -----------------
    rules, rule_errors = load_detection_rules()
    errors.extend(rule_errors)

    referenced_rules = coverage_rule_ids(coverage)
    referenced_rules |= set(lower.get("detection_rules", []) or [])
    referenced_rules |= set(higher.get("detection_rules", []) or [])

    for rid in sorted(referenced_rules - set(rules.keys())):
        errors.append(
            f"Detection rule id '{rid}' is referenced in coverage/profiles but "
            f"no file in detections/ declares it (phantom mapping)."
        )

    # --- correlation legs must resolve -----------------------------------
    uuid_to_rid = {
        rule["data"].get("id"): rid
        for rid, rule in rules.items()
        if rule["data"].get("id")
    }
    leg_targets: set[str] = set()
    for rid, rule in rules.items():
        corr = rule["data"].get("correlation") or {}
        for leg in corr.get("rules", []) or []:
            leg_rid = leg if leg in rules else uuid_to_rid.get(leg)
            if leg_rid is None:
                errors.append(
                    f"Correlation rule '{rid}' references unknown rule '{leg}'."
                )
            else:
                leg_targets.add(leg_rid)
                if leg_rid == rid:
                    errors.append(f"Correlation rule '{rid}' references itself.")

    # --- orphan rules (not in coverage/profiles, not a correlation leg) --
    for rid in sorted(set(rules.keys()) - referenced_rules - leg_targets):
        errors.append(
            f"Detection rule '{rid}' exists in detections/ but is referenced "
            f"neither by the coverage matrix/profiles nor by a correlation rule."
        )

    # --- lower profile must not require FLD-E ----------------------------
    lower_rule_ids = set(lower.get("detection_rules", []) or [])
    for rid in sorted(lower_rule_ids):
        rule = rules.get(rid)
        if not rule:
            continue  # unresolvable ids already reported above
        if "FLD-E" in (rule["data"].get("zokb_required_fields", []) or []):
            errors.append(
                f"Lower profile detection rule {rid} requires FLD-E, which is not allowed."
            )

    # --- semantic fit (warnings, non-blocking) ---------------------------
    class_ecs = load_event_class_ecs()
    for regime in (coverage.get("coverage", {}) or {}).values():
        for evt, mapped in (regime.get("event_classes", {}) or {}).items():
            ecs = class_ecs.get(evt, {})
            class_cats = ecs.get("event.category", []) or []
            class_types = ecs.get("event.type", []) or []
            for rid in (mapped or {}).get("detection_rules", []) or []:
                rule = rules.get(rid)
                if not rule or "detection" not in rule["data"]:
                    continue  # correlation rules: no selections to compare
                detection = rule["data"]["detection"]
                rule_cats = selection_values(detection, "event.category")
                rule_types = selection_values(detection, "event.type")
                if rule_cats and class_cats and not intersection(rule_cats, class_cats):
                    warnings.append(
                        f"Rule '{rid}' event.category {sorted(rule_cats)} does not "
                        f"overlap {evt} categories {class_cats}."
                    )
                if rule_types and class_types and not intersection(rule_types, class_types):
                    warnings.append(
                        f"Rule '{rid}' event.type {sorted(rule_types)} does not "
                        f"overlap {evt} types {class_types}."
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
    # --- technology mapping layer (optional, non-normative) --------------
    technologies, tech_errors = load_technologies()
    errors.extend(tech_errors)

    mapped_pairs: set[tuple[str, str]] = set()
    for tid, tdata in technologies.items():
        for block in tdata.get("implements", []) or []:
            sid = block.get("source")
            if sid not in sources:
                errors.append(
                    f"Technology {tid} references unknown source '{sid}'."
                )
                continue
            emitted = set(sources[sid].get("must_emit_event_classes", []) or [])
            for evt in (block.get("event_mappings") or {}):
                if evt not in evt_ids:
                    errors.append(
                        f"Technology {tid} maps unknown event class '{evt}' "
                        f"under source '{sid}'."
                    )
                elif evt not in emitted:
                    errors.append(
                        f"Technology {tid} maps '{evt}' under source '{sid}' but that "
                        f"source does not emit it (missing from must_emit_event_classes)."
                    )
                else:
                    mapped_pairs.add((sid, evt))

    for sid, sdata in sources.items():
        for evt in sdata.get("must_emit_event_classes", []) or []:
            if (sid, evt) not in mapped_pairs:
                warnings.append(
                    f"No technology mapping for ({sid}, {evt}) -- optional layer, "
                    f"informational only."
                )

    for w in warnings:
        print(f"WARNING: {w}")

    if errors:
        print("Coverage validation FAILED:")
        for e in errors:
            print(f"- {e}")
        return 1

    suffix = f" ({len(warnings)} warning(s))" if warnings else ""
    print(f"Coverage validation PASSED{suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())