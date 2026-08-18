# AGENTS.md - Project Instructions for zokb-siem-baseline

This repository implements a vendor-neutral compliance-as-code baseline for Czech ZoKB/NIS2 logging and detection requirements. 

## Project Architecture
The project follows a 4-layer model:
1. **OSCAL Legal Catalogs (`catalog/`)**: Machine-readable legal requirements from Czech decrees (vyhláška 409/2025 and 410/2025).
2. **Logging Baseline (`logging/`)**: Event classes and required fields mapped to common standards (ECS/OCSF).
3. **Detection Baseline (`detections/`)**: Portable Sigma rules.
4. **Coverage & CI (`mappings/`, `tools/`, `.github/workflows/`)**: Traceability and validation.

## Core Concepts
- **Regime Model**: There are two regimes: `higher` (vyhl. 409/2025) and `lower` (vyhl. 410/2025). Differences are managed via profiles in `profiles/*.yaml`.
- **Compliance-as-Code**: Legal text is captured in OSCAL `prose`, while engineering interpretations are marked as `note`.
- **Traceability**: Every log source and detection rule should map back to a legal requirement via `mappings/coverage.yaml`.
- **Source Scoping**: Log sources are scoped by *event plane*, not by device type. Access-decision events (802.1X auth, VPN sessions, perimeter denies; subject = the supplicant/client/flow at an edge) and device-management events (admin logons, config changes, health; subject = the admin on the box) are separate collection contracts even when one appliance emits both. New sources must declare which plane each class belongs to in their `note`.

## Agent Skills & Guidelines

### 1. Adding Log Sources
When asked to add a new log source, follow the "2-file edit" rule:
- Define the source in `logging/sources/{source_name}.yaml`.
- Wire the source in `mappings/coverage.yaml`.
- Ensure the source only references event classes and fields that exist in `logging/event-classes.yaml` and `logging/required-fields.yaml`.
- Optionally, add a third file under `logging/technologies/` mapping the source's event classes to concrete vendor/product telemetry (Windows Event IDs, syslog mnemonics, cloud event names, etc.). This layer is **entirely optional and non-normative** — see `logging/technologies/README.md`. CI hard-fails an *invalid* technology file but never fails on a missing one; do not treat this as a requirement.

### 2. Creating Detections
- Write detections in **Sigma format** within the `detections/` directory.
- Ensure rules are portable and do not use vendor-specific extensions unless absolutely necessary.
- Every rule MUST declare a stable `zokb_rule_id: zokb-<category>-<name>` (kebab-case) plus `date:` and `modified:` fields — CI hard-fails if a `detection_rules` entry in `mappings/coverage.yaml` does not resolve to a rule's `zokb_rule_id`.
- Refresh `modified:` whenever a rule is substantively reviewed or edited; `tools/staleness_check.py` flags rules stale past the review window (see `docs/detection-lifecycle.md`).
- Map the detection to the appropriate legal control in `mappings/coverage.yaml`.
- Evaluation/process obligations (vyhl. 409/2025 §23, vyhl. 410/2025 §9(1)(d/e)) that are not Sigma-shaped get tracked in `mappings/controls-coverage.yaml` (control → status/owner/artifacts). If a change implements or affects one, update its status/artifacts there.

### 3. Validation & Testing
Before submitting changes, always verify consistency:
- Run the coverage check: `python3 tools/coverage_check.py` (hard gate).
- Run the staleness check: `python3 tools/staleness_check.py` (currently advisory in CI).
- Validate YAML files against the JSON schemas in `schema/`.
- Lint Sigma portability: CI runs `sigma check` over all `detections/**/*.yml` (best effort); `sigma convert` against Splunk/Sentinel backends is exercised for representative rules.

### 4. Legal Accuracy
- Do not modify verbatim legal text in OSCAL files.
- When adding engineering notes, clearly separate them from the legal prose.
- Refer to the `README.md` for the breakdown of obligations between higher and lower regimes.

## Directory Map
- `catalog/`: Legal requirements (OSCAL)
- `logging/`: Event definitions and field requirements
  - `logging/technologies/`: Optional, non-normative layer mapping abstract sources/event-classes to concrete vendor telemetry (Windows Event IDs, syslog mnemonics, etc.) — see `logging/technologies/README.md`
- `detections/`: Sigma detection rules
- `mappings/`: Coverage and traceability matrices (`coverage.yaml` source↔class↔rule wiring; `controls-coverage.yaml` evaluation/process-control tracking; dated gap-analysis reports)
- `profiles/`: Regime-specific configurations
- `schema/`: JSON schemas for validation
- `tools/`: Validation scripts (`coverage_check.py` hard gate, `staleness_check.py` advisory, `parse_detection.py` QRadar round-trip tooling)
- `docs/`: Engineering guidance (architecture diagrams, `detection-lifecycle.md` review-cadence policy)
- `ctu_qradar/`: Institution-specific QRadar implementation of the baseline (own schema, content YAML and validation tools; changes there are separate from the vendor-neutral layers above)
