# Technology mapping layer

`logging/technologies/*.yaml` is an **optional, non-normative** layer. It maps
abstract `(source, event-class)` pairs from `logging/sources/*.yaml` and
`logging/event-classes*.yaml` to the concrete telemetry a specific product or
organisational deployment actually emits -- the same relationship "Windows
Event ID 4624" has to the abstract class "logon/logoff incl. failures".

## Why this exists

The vendor-neutral baseline (`logging/sources/`, `logging/event-classes*.yaml`,
`mappings/coverage.yaml`) defines **what must be logged**, in terms that hold
across any vendor. It deliberately says nothing about *which* Windows Event ID,
FortiOS `logid`, or Kubernetes audit verb realizes a given class -- that detail
is vendor- and deployment-specific, and baking it into the normative layer
would tie compliance to product internals that vendors renumber over time.

This layer exists so an adopting organisation can add that missing, concrete
detail **as context**, without ever making it a compliance requirement:

- Onboarding engineers get a worked answer to "which Windows/FortiOS/AWS event
  actually satisfies EVT-22-3-A on our estate?"
- Multiple technologies, or multiple organisational deployments of the same
  technology, can coexist side by side.
- No vendor, source, or event class is ever *required* to have a mapping. The
  baseline is complete without a single file in this directory.

## Normativity: "valid if present"

- A technology file that does not exist is never an error.
- A technology file that **does** exist must be structurally valid and must
  not over-claim: `tools/coverage_check.py` **hard-fails** on unknown
  `SRC-*`/`EVT-*` references, on an event class mapped under a source that
  doesn't actually emit it, and on convention violations (see below).
- **Coverage gaps are advisory only.** `(source, event-class)` pairs with no
  mapping in any technology file produce a `WARNING:` line, never a failure.
  This mirrors `tools/staleness_check.py`'s advisory tier.

## File conventions

- **Filename** = `{org-}{vendor}-{product}.yaml`, kebab-case, matching the
  `id`: `windows-security.yaml` <-> `id: TECH-WINDOWS-SECURITY`.
  Organisation-scoped files prefix the org: `ctu-fortigate.yaml` <->
  `id: TECH-CTU-FORTIGATE` with `org: ctu` set.
- **ID grammar**: `TECH-[<ORG>-]<VENDOR>-<PRODUCT>` (upper-kebab), unique
  across the directory. The validator checks filename <-> id <-> `org`
  consistency.
- **Scope**: one file = one technology (a product or telemetry stream),
  possibly spanning multiple sources via separate `implements` blocks. Never
  one file per abstract source, and never one file dumping an org's entire
  estate.
- **Baseline vs. org files**: files without `org` are vendor-generic
  references maintained with the baseline (currently only
  `windows-security.yaml`, migrated from the former embedded
  `windows_events` blocks). Files with `org` carry organisational context and
  are never assumed portable to other deployments of the same product. Both
  kinds live in this directory under identical validation.

## File shape

```yaml
id: TECH-CTU-FORTIGATE
title: CTU perimeter FortiGate cluster (FG-1800F, FortiOS 7.4)
vendor: fortinet
product: fortigate
org: ctu                         # optional; omit for vendor-generic references
implements:
  - source: SRC-FIREWALL         # access-decision plane
    event_mappings:
      EVT-22-3-B:
        - id: logid=0000000013
          channel: traffic
          record: Forward traffic denied by policy
          outcome: failure
  - source: SRC-NETDEV           # device-management plane -- same appliance,
    event_mappings:               # separate block: never merge planes
      EVT-22-3-A:
        - id: logid=0100032001
          channel: event
          record: Admin login to GUI/CLI
          outcome: success
note: >-
  CTU organisational context; log IDs verified against our FortiOS 7.4
  estate. Not assumed portable to other FortiGate deployments.
```

Each event class maps to a list of **signals**: `id` (required), `record`
(required, human description), and optional `channel`, `mnemonic`, `outcome`
(`success | failure | any`).

### `id` is documentation, not a query

`id` is a vendor-native selector string, not a machine-parseable identifier.
For technologies with real event IDs it looks like one (`"4624"`,
`"%ASA-4-106023"`, `"ConsoleLogin"`). For technologies with no native event ID
-- Kubernetes audit logs, RADIUS packet types -- it is a free-form field-match
expression describing how to recognize the event, e.g.:

```yaml
EVT-22-3-C:
  - id: verb=create resource=rolebindings
    channel: kube-apiserver-audit
    record: RoleBinding created
```

**Do not build automation that assumes `id` is machine-resolvable.** It is not
unique either: the same signal legitimately recurs under multiple event
classes (Windows `4688` satisfies several `EVT-22-3-*` classes).

## Emission vs. consumption

This layer describes *emission*: what a device or platform logs.

## Relationship to Sigma `logsource`

Sigma rules under `detections/` already carry their own `logsource` targeting
(`product: windows`, `service: security`) used by `sigma convert` against
concrete SIEM backends. This layer is the baseline-side class -> telemetry
realization map; it does not replace or feed Sigma's `logsource` field -- the
two operate at different layers (class realization vs. rule targeting).

## Relationship to `docs/vendor-product-mapping.md`

`docs/vendor-product-mapping.md` remains a broad, non-normative survey across
many vendors -- useful before an organisation has authored its own technology
file. If a `TECH-*` file exists for a given vendor/product, **it wins**; the
doc should be reconciled if the two ever disagree.
