# Architecture & dependency graph

This document visualizes how the artifacts in this repository depend on each
other, from the authoritative legal text down to vendor SIEM queries.

> **Rendering note.** The diagrams below use [Mermaid](https://mermaid.js.org/),
> which **GitHub renders natively** in Markdown. In **VS Code**, the built-in
> preview does *not* support Mermaid — install the extension
> **"Markdown Preview Mermaid Support"** (`bierner.markdown-mermaid`) and reopen
> the preview (`Ctrl/Cmd+Shift+V`). A plain-text (ASCII) fallback is included
> under each diagram for environments without Mermaid.

---

## 1. The 4-layer model (full dependency graph)

```mermaid
flowchart TD
    subgraph L0["⚖️ Legal layer"]
        ZAKON["zákon 264/2025 Sb."]
        V409["vyhláška 409/2025 · §§ 21–23 · higher"]
        V410["vyhláška 410/2025 · § 9 · lower"]
    end

    subgraph L1["📜 Catalog layer · OSCAL"]
        CAT409["catalog/vyhlaska-409-2025.oscal.yaml"]
        CAT410["catalog/vyhlaska-410-2025.oscal.yaml"]
        CTL["catalog/detection-controls.yaml"]
    end

    subgraph L2["🎯 Profile layer · regime baselines"]
        PH["profiles/higher.yaml"]
        PL["profiles/lower.yaml"]
    end

    subgraph L3["🧱 Logging baseline · ECS / OCSF"]
        EC["logging/event-classes.yaml"]
        ECD["logging/event-classes-detection.yaml"]
        RF["logging/required-fields.yaml"]
        SRC["logging/sources/*.yaml"]
        TECH["logging/technologies/*.yaml<br/>(optional, non-normative)"]
    end

    subgraph L4["🔍 Detections · Sigma"]
        SIG["detections/**/*.yml"]
        COR["failed-logons-correlation.yml"]
    end

    subgraph L5["✅ Assurance"]
        COV["mappings/coverage.yaml"]
        SCHEMA["schema/*.schema.json"]
        CI[".github/workflows/validate.yml"]
    end

    ZAKON --> V409 --> CAT409
    ZAKON --> V410 --> CAT410
    CAT409 --> PH
    CAT410 --> PL
    CTL --> PH
    CTL --> PL
    CAT409 --> EC
    CTL --> ECD
    EC --> RF
    ECD --> RF
    EC --> SRC
    ECD --> SRC
    SRC -.->|optional| TECH
    EC -.->|optional| TECH
    EC --> SIG
    ECD --> SIG
    RF --> SIG
    SIG --> COR
    PH --> COV
    PL --> COV
    SIG --> COV
    SRC --> COV
    COV --> CI
    SCHEMA --> CI
    SIG --> CI

    classDef law fill:#fde2e2,stroke:#c0392b,color:#000;
    classDef cat fill:#e8f0fe,stroke:#2c5fb3,color:#000;
    classDef prof fill:#fff4d6,stroke:#b8860b,color:#000;
    classDef log fill:#e6f6ec,stroke:#1e8449,color:#000;
    classDef opt fill:#f5f5f5,stroke:#999,color:#000,stroke-dasharray: 4 2;
    classDef rule fill:#f0e6fa,stroke:#7d3c98,color:#000;
    classDef ci fill:#eaeaea,stroke:#555,color:#000;

    class ZAKON,V409,V410 law;
    class CAT409,CAT410,CTL cat;
    class PH,PL prof;
    class EC,ECD,RF,SRC log;
    class TECH opt;
    class SIG,COR rule;
    class COV,SCHEMA,CI ci;
```

<details>
<summary>ASCII fallback</summary>

```text
⚖️  LEGAL
    zákon 264/2025 Sb.
    ├─► vyhláška 409/2025  (§§ 21–23 · higher regime)
    └���► vyhláška 410/2025  (§ 9 · lower regime)

📜  CATALOG (OSCAL)                      derived from the decrees
    409 ─► catalog/vyhlaska-409-2025.oscal.yaml
    410 ─► catalog/vyhlaska-410-2025.oscal.yaml
           catalog/detection-controls.yaml      (shared CTL-*)

🎯  PROFILES (regime baselines)
    cat-409 + detection-controls ─► profiles/higher.yaml
    cat-410 + detection-controls ─► profiles/lower.yaml

🧱  LOGGING BASELINE (ECS / OCSF)
    cat-409             ─► logging/event-classes.yaml            (§22(3) a–j)
    detection-controls  ─► logging/event-classes-detection.yaml  (§9(1) a–c)
    event-classes (×2)  ─► logging/required-fields.yaml          (FLD-A…F)
    event-classes (×2)  ─► logging/sources/*.yaml                (win/linux/fw)
    sources + classes   ┄► logging/technologies/*.yaml           (optional, non-normative)

🔍  DETECTIONS (Sigma)
    event-classes + required-fields ─► detections/**/*.yml
    base rule                       ─► detections/auth/failed-logons-correlation.yml (§23)

✅  ASSURANCE
    profiles + sources + detections          ─► mappings/coverage.yaml
    coverage + schema/*.json + detections    ─► .github/workflows/validate.yml  ✔ / ✘
```

</details>

---

## 2. End-to-end trace of one obligation (§22(3)(a) → SIEM)

This shows a single legal requirement flowing all the way to vendor queries —
the view an auditor cares about.

```mermaid
flowchart LR
    A["§22 (3)(a)<br/>logon/logoff incl. failures"]:::law
    B["EVT-22-3-A<br/>event class · ECS/OCSF"]:::event
    C["FLD-A … FLD-F<br/>required fields"]:::field
    D["sources/windows.yaml<br/>sources/firewall.yaml"]:::src
    E["failed-logons-bruteforce.yml<br/>Sigma base rule"]:::rule
    F["failed-logons-correlation.yml<br/>§23 (1)(a)"]:::rule
    G["coverage.yaml"]:::cov
    H["SIEM queries<br/>Splunk · Sentinel · Elastic"]:::siem

    A --> B --> C
    B --> D
    B --> E
    C --> E
    E --> F
    E --> G
    F --> G
    E --> H
    F --> H

    classDef law fill:#fde2e2,stroke:#c0392b,color:#000;
    classDef event fill:#e6f6ec,stroke:#1e8449,color:#000;
    classDef field fill:#e6f6ec,stroke:#1e8449,color:#000;
    classDef src fill:#fff4d6,stroke:#b8860b,color:#000;
    classDef rule fill:#f0e6fa,stroke:#7d3c98,color:#000;
    classDef cov fill:#eaeaea,stroke:#555,color:#000;
    classDef siem fill:#e8f0fe,stroke:#2c5fb3,color:#000;
```

<details>
<summary>ASCII fallback</summary>

```text
 §22(3)(a)            EVT-22-3-A           required-fields         Sigma base rule
 logon/logoff   ──►   event class    ──►   FLD-A … FLD-F    ──►    failed-logons-
 incl. failures       (ECS/OCSF)           (mandatory)             bruteforce.yml
                           │                                            │
                           ▼                                            ▼
                      sources/                                     correlation rule
                      windows.yaml                                 failed-logons-
                      firewall.yaml                                correlation.yml (§23)
                                                                        │
                          mappings/coverage.yaml  ◄────────────────────┤
                                                                        ▼
                          SIEM queries:  Splunk · Sentinel · Elastic · QRadar
```

</details>

---

## 3. Regime tailoring (one catalog → two baselines)

```mermaid
flowchart TB
    CAT["Shared catalog<br/>controls · event classes · fields"]:::cat

    CAT --> PH["profiles/higher.yaml · 409"]:::prof
    CAT --> PL["profiles/lower.yaml · 410"]:::prof

    PH --> H1["6 fields A–F"]
    PH --> H2["§22(3) a–j mandatory"]
    PH --> H3["§23 correlation required"]
    PH --> H4["retention ≥ 18 months"]
    PH --> H5["central collector + NTP + log integrity"]
    PH --> H6["IDs stable across re-IP"]

    PL --> L1["4 fields · no FLD-E"]
    PL --> L2["event classes recommended"]
    PL --> L3["correlation optional"]
    PL --> L4["retention self-determined"]
    PL --> L5["central / NTP / integrity optional"]
    PL --> L6["no re-IP stability clause"]

    classDef cat fill:#e8f0fe,stroke:#2c5fb3,color:#000;
    classDef prof fill:#fff4d6,stroke:#b8860b,color:#000;
```

<details>
<summary>ASCII fallback</summary>

```text
                    Shared catalog
            (controls · event classes · fields)
                     │                │
          ┌──────────┘                └──────────┐
          ▼                                      ▼
    profiles/higher.yaml                   profiles/lower.yaml
    (409 · higher regime)                  (410 · lower regime)
          │                                      │
          ├─ 6 fields  A–F                       ├─ 4 fields  (no FLD-E)
          ├─ §22(3) a–j  MANDATORY               ├─ event classes  recommended
          ├─ §23 correlation  REQUIRED           ├─ correlation  optional
          ├─ retention ≥ 18 months               ├─ retention  self-determined
          ├─ central + NTP + log integrity       ├─ those controls  optional
          └─ IDs stable across re-IP             └─ no re-IP stability clause
```

</details>

---

## Legend

| Color | Layer |
|---|---|
| 🔴 red | Legal text (authoritative decrees) |
| 🔵 blue | OSCAL catalogs / shared controls |
| 🟡 yellow | Regime profiles |
| 🟢 green | Logging baseline (event classes, fields, sources) |
| 🟣 purple | Sigma detection rules |
| ⚪ grey | Coverage / schema / CI assurance |
