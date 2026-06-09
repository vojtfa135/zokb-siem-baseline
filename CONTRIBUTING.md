# Contributing

This repository is a **compliance-as-code baseline**: legal requirements from the
Czech ZoKB decrees (vyhláška 409/2025 and 410/2025) expressed as machine-readable
artifacts. Most contributions fall into one of a few well-defined shapes. Keep
**verbatim legal text** (`ref:` / OSCAL `prose`) separate from **engineering
interpretation** (`note:`).

Before opening a PR, run the local checks:

```bash
python3 tools/coverage_check.py
```

CI (`.github/workflows/validate.yml`) additionally validates every YAML file
against the JSON Schemas in `schema/` and best-effort lints/converts the Sigma
rules.

---

## Adding a new log source

This is the most common change. A log source declares **what an appliance must
emit** (which event classes and which fields). It is a **2-file change**; CI
verifies the wiring.

### Step 1 — Create the source definition

Add a file under `logging/sources/<name>.yaml`. It must satisfy
`schema/source.schema.json`, which requires: `id`, `title`, `transport`
(`protocol` + `format`), `must_emit_event_classes`, `must_emit_fields`, `note`.

```yaml
id: SRC-IDP                       # unique, SRC-* convention
title: Identity provider (Entra ID / Okta)
auth_scope: cloud                 # optional, free-form
transport:
  protocol: https-api
  format: json
must_emit_event_classes:          # every id MUST already exist (see below)
  - EVT-22-3-A
  - EVT-22-3-B
  - EVT-22-3-C
  - EVT-22-3-D
must_emit_fields:                 # every id MUST already exist (see below)
  - FLD-A
  - FLD-B
  - FLD-C
  - FLD-D
  - FLD-E
  - FLD-F
note: Cloud IdP sign-in and audit logs.
```

Rules enforced by `tools/coverage_check.py`:

- **`id` must be unique** across all files in `logging/sources/` and follow the
  `SRC-*` convention (existing: `SRC-WINDOWS`, `SRC-LINUX`, `SRC-FIREWALL`,
  `SRC-IDP`).
- **Every `EVT-*`** you list must already be defined in
  `logging/event-classes.yaml` (§22(3) a–j) or
  `logging/event-classes-detection.yaml` (§9(1) a–c).
- **Every `FLD-*`** you list must already be defined in
  `logging/required-fields.yaml` (FLD-A … FLD-F).

If your source genuinely emits something new, add the event class first (see
"Adding a new event class" below).

> **Regime note.** In the **higher** regime emit all six fields (incl. `FLD-E`,
> originating device id) and keep `host.id` / `user.id` stable across network
> re-identification (§22(4)). In the **lower** regime `FLD-E` is not mandatory.

### Step 2 — Wire it into the coverage matrix

Add the new source `id` to the `log_sources` list of each event class it feeds in
`mappings/coverage.yaml`. A source that is **not** referenced anywhere is treated
as an **orphan** and fails CI.

```yaml
      EVT-22-3-A:
        log_sources: [SRC-WINDOWS, SRC-LINUX, SRC-FIREWALL, SRC-IDP]   # <- add
        detection_rules: [zokb-auth-failed-logons-bruteforce, zokb-auth-failed-logons-correlation]
```

### Step 3 (optional) — Add a detection if the source unlocks new coverage

If the source merely strengthens existing event classes, you are done. If it
lets you detect something not yet covered (e.g. impossible-travel sign-ins from
an IdP), add a Sigma rule under `detections/` and reference its id in the
matrix's `detection_rules`.

See `logging/sources/idp.yaml` for a complete worked example.

---

## Adding a new event class

1. Add an entry to `logging/event-classes.yaml` (§22(3) classes) or
   `logging/event-classes-detection.yaml` (§9(1) detection classes) with: `id`
   (`EVT-*`), `ref` (control id), `title`, `ecs`, `ocsf`, `attack`, `outcomes`,
   and `required_fields`.
2. Reference it from at least one log source (`must_emit_event_classes`).
3. For the higher regime, add it to `profiles/higher.yaml` (mandatory /
   recommended) and give it a `mappings/coverage.yaml` entry with at least one
   `log_sources` and one `detection_rules` value — otherwise CI fails.

## Adding a new detection rule

1. Add a Sigma rule under `detections/<category>/<name>.yml` using ECS-style
   fields.
2. Include a `fields:` list guaranteeing the regime's required fields
   (§22(4) / §9(2)) are present.
3. Tag it with the legal namespace, e.g. `zokb.v409.par22.3.a`,
   `zokb.v410.par9.1.b`, plus relevant `attack.*` tags.
4. Reference its id from `mappings/coverage.yaml`.
5. **Lower-regime rules must not require `FLD-E`** (CI enforces this).

## Editing legal catalogs

The OSCAL catalogs in `catalog/` carry the **normative** Czech text in `prose`.
Do not paraphrase it. Put any interpretation in a `note` part. Keep control ids
stable (`v409-22.4.e`, `v410-9.1.b`, …) because profiles, event classes, and
fields reference them.

---

## Licensing of contributions

- Catalog / legal-mapping content: **CC0-1.0** (`LICENSE-CC0`).
- Sigma rules and tooling: **MIT** (`LICENSE-MIT`).

By contributing you agree your changes are released under the corresponding
license for that part of the tree.
