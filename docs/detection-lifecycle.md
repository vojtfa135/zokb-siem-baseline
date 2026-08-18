# Detection rule lifecycle policy

This document defines the operational process obligations of vyhl. 409/2025
§23 and vyhl. 410/2025 §9(1)(d)(e) that cannot be expressed as Sigma rules.
It is referenced from `mappings/controls-coverage.yaml`.

## 1. Review cadence (§23(2)(b)(c), §9(1)(e))

- Every detection rule carries `date:` (first authoring) and `modified:`
  (last substantive review). A **review** means confirming the logic still
  matches the threat and the telemetry, not necessarily editing it — refresh
  `modified:` when a review concludes the rule is still valid.
- Review window: **365 days** per rule. `tools/staleness_check.py` reports
  rules past this window. CI runs it in **warn mode**; after the first full
  review cycle the team should switch it to `--fail` (hard gate).
- New attack research triggering an out-of-band rule update follows the
  normal PR flow with the rule's `modified:` bumped.

## 2. False-positive reduction duty (§23(2)(a))

- Every rule **must** carry a `falsepositives:` field documenting known
  benign triggers — this is enforced informally by review and linted
  manually today.
- Broad audit-style detections (e.g. all denied perimeter traffic, all
  privileged activity) MUST be `level: informational` or `low` and paired
  with either a tuned subset rule or a thresholded `event_count`
  correlation for the actionable signal. Rationale: the law requires
  *evaluation* of the records, not paging on each one.
- SOC reviews aggregate alert volumes quarterly; rules consistently above
  agreed noise budgets are tuned, re-levelled or retired (record the
  decision in the PR, which is the audit trail).

## 3. ISMS feedback loop (§23(3))

- Alert statistics (volume per rule, disposition) feed the quarterly review
  above.
- Confirmed incidents traceable to a detection are noted in the rule's
  description or references (retrofit in the post-incident PR).
- Tuning decisions and retirements are changes to this repository; the git
  history constitutes the change log required by the ISMS.

## 4. Early warning (§23(1)(b), §9(1)(d))

- Rule `level:` encodes alerting priority (`high` = page/ticket now,
  `medium` = queue, below = hunt/audit). The notification pipeline
  (webhook/SOAR/on-call) is a deployment concern and intentionally out of
  scope for this vendor-neutral baseline.

## 5. Documented detection limitations and follow-ups

Engineering constraints that deployment teams must close at the SIEM layer:

1. **Impossible travel.** `zokb-auth-multi-source-logon` counts distinct
   `source.ip` values per account — a coarse approximation. True
   impossible-travel detection requires geolocation enrichment of
   `source.ip` (VPN and IdP sources currently emit the IP only). Follow-up:
   add `source.geo.*` enrichment and a distance/velocity check in the SIEM.
2. **Actor ≠ target comparison.** Sigma cannot compare two fields
   (`user.id` vs `target user`). `zokb-iam-credential-reset-non-owner` and
   `zokb-iam-persistence-chain-correlation` therefore defer the
   actor-versus-target discrimination to SIEM-side filters; the correlation
   leg keys should be mapped to the *target* account during onboarding.
3. **First-time-seen baselines.** "First logon from a new device/source"
   requires reference-data (watched baselines) that Sigma cannot express
   portably; implement via SIEM reference sets seeded from retention data.