#!/usr/bin/env python3
"""Report detection rules whose last review is older than the policy window.

Implements the rule-update-cadence obligations vyhl. 409/2025 §23(2)(b)(c)
and vyhl. 410/2025 §9(1)(e): every rule carries a `modified:` date that must
be refreshed whenever the rule is reviewed (see docs/detection-lifecycle.md).
A rule older than --threshold-days is reported as stale.

Default mode is advisory (exit 0). Pass --fail to turn stale rules into a
hard CI failure once the review process has proven itself in practice.

Dependencies: PyYAML only.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_THRESHOLD_DAYS = 365


def _as_date(value) -> datetime.date | None:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold-days", type=int, default=DEFAULT_THRESHOLD_DAYS,
        help="rules untouched for longer than this are reported as stale "
             f"(default: {DEFAULT_THRESHOLD_DAYS})",
    )
    parser.add_argument(
        "--fail", action="store_true",
        help="exit 1 when any rule is stale (default: warn only, exit 0)",
    )
    parser.add_argument(
        "--today",
        help="override today's date (YYYY-MM-DD) for testing",
    )
    args = parser.parse_args()

    today = _as_date(args.today) if args.today else datetime.date.today()
    if today is None:
        print(f"Invalid --today value: {args.today}", file=sys.stderr)
        return 2

    stale: list[tuple[str, datetime.date, int]] = []
    for rule_path in sorted((ROOT / "detections").rglob("*.yml")):
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
        rel = rule_path.relative_to(ROOT)
        rid = data.get("zokb_rule_id") or rel.name
        last_touch = _as_date(data.get("modified")) or _as_date(data.get("date"))
        if last_touch is None:
            print(f"WARN: {rid} ({rel}) has no usable modified:/date: field.")
            continue
        age = (today - last_touch).days
        if age > args.threshold_days:
            stale.append((rid, last_touch, age))

    if stale:
        print(f"Stale detection rules (>{args.threshold_days} days since review):")
        for rid, last_touch, age in sorted(stale, key=lambda s: -s[2]):
            print(f"- {rid}: last review {last_touch} ({age} days ago)")
        print(
            "\nAction: review the rule and refresh its `modified:` date, or "
            "retire/replace it (docs/detection-lifecycle.md)."
        )
        return 1 if args.fail else 0

    print(f"All detection rules reviewed within {args.threshold_days} days.")
    return 0


if __name__ == "__main__":
    sys.exit(main())