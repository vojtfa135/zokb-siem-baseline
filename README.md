# zokb-siem-baseline

Vendor-neutral **compliance-as-code baseline** for Czech ZoKB/NIS2 logging and detection requirements.

## Scope and model

This repository implements a 4-layer model:

1. **OSCAL legal catalogs** (`catalog/`) – machine-readable legal requirements.
2. **Logging baseline** (`logging/`) – event classes and required fields mapped to ECS/OCSF.
3. **Detection baseline** (`detections/`) – Sigma rules portable across SIEM backends.
4. **Coverage and CI** (`mappings/`, `tools/`, `.github/workflows/`) – traceability and automatic checks.

> 📊 See **[docs/architecture.md](docs/architecture.md)** for dependency graphs visualizing how these layers connect (Mermaid diagrams with ASCII fallbacks).

## Regime model (single shared baseline + profile dimension)

The shared baseline is represented in `logging/*` and `catalog/detection-controls.yaml`.
`profiles/higher.yaml` and `profiles/lower.yaml` tailor the same baseline for each regime.

| Topic | Higher obligations (vyhl. 409/2025) | Lower obligations (vyhl. 410/2025) |
|---|---|---|
| Event fields | FLD-A..FLD-F required | FLD-A, FLD-B, FLD-C, FLD-D, FLD-F required (FLD-E not mandatory) |
| Stable IDs across re-IP | Required for asset/account/device IDs (§22(4)(c)(d)(e)) | Not explicitly mandated in §9 |
| Account identifier strength | Unique account ID required (§22(4)(d)) | Account identification required (§9(2)(b)(3)) |
| Correlation/SIEM continuous evaluation | Required (§23) | Not explicitly required (recommended) |
| Centralized collection, integrity, NTP | Required (§22(5)(a)(b), §22(6)) | Recommended (engineering baseline) |
| Retention | At least 18 months (§22(5)(c)) | Self-determined by security needs, must be documented (§9(3)) |

## Legal sources

- zákon č. 264/2025 Sb. (parent act)
- vyhláška č. 409/2025 Sb. (higher-obligations regime)
- vyhláška č. 410/2025 Sb. (lower-obligations regime)

Verbatim legal text is captured in OSCAL `prose`. Engineering interpretation is marked as `note`.

## Sigma portability

Example conversions (best effort in CI):

```bash
sigma convert -t splunk detections/auth/failed-logons-bruteforce.yml
sigma convert -t sentinel detections/network/perimeter-block.yml
```

## Validation

CI validates:
- YAML files against JSON schemas in `schema/`
- coverage consistency via `tools/coverage_check.py`
- Sigma lint/conversion on a best-effort basis

Run locally:

```bash
python3 tools/coverage_check.py
```

## Licensing

- **CC0-1.0** (`LICENSE-CC0`) for legal mappings/catalog content.
- **MIT** (`LICENSE-MIT`) for Sigma rules and tooling.

## Disclaimer

The verbatim decree text is authoritative law. This repository provides engineering mappings for implementation support and auditability; it is **not legal advice**.
