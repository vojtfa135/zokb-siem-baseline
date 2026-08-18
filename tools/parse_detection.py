#!/usr/bin/env python3
"""Parse QRadar detection rule test fields into a structured schema
and emit QRadar syntax back for round-trip validation.

Usage:
  python3 tools/parse_detection.py --check detection-rules.yaml
      Parse every rule's test field, emit QRadar text, diff against original.
      Exits non-zero if any rule fails to round-trip.

  python3 tools/parse_detection.py --transform detection-rules.yaml
      Replace the raw `test` field with structured `detection` on every rule.
      Backs up the original file to detection-rules.yaml.bak.
      Keeps `detection_raw` alongside for audit verification.

  python3 tools/parse_detection.py --drop-raw detection-rules.yaml
      After verifying round-trips, drop the `detection_raw` audit fields.
"""

from __future__ import annotations

import re
import sys
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════════════════
#  PARSER
# ═══════════════════════════════════════════════════════════════════════

def parse_test(text: str) -> dict:
    """Parse raw QRadar test text into structured detection dict."""
    prefix_m = re.match(
        r'Apply (.+?) on events which are detected by the (.+?)'
        r'(?=\s+and\s+(?:NOT\s+)?when\s+|\s*$)',
        text, re.DOTALL
    )
    if not prefix_m:
        raise ValueError(f"Cannot parse prefix from: {text[:80]}...")

    name = prefix_m.group(1).strip()
    scope = prefix_m.group(2).strip()
    remaining = text[prefix_m.end():].strip()
    # Strip the leading "and " connector between prefix and first condition
    if remaining.lower().startswith('and '):
        remaining = remaining[4:].strip()
    condition_texts = re.split(r'\s+and\s+(?=NOT\s+when\s+|when\s+)', remaining)
    logic = []
    for ct in condition_texts:
        ct = ct.strip()
        if not ct:
            continue
        pred = _parse_condition(ct)
        if pred:
            logic.append(pred)

    return {'name': name, 'scope': scope, 'logic': logic}


def _parse_condition(text: str) -> dict | None:
    for pattern, handler in _PATTERNS:
        m = re.match(pattern, text, re.DOTALL)
        if m:
            return handler(m)
    raise ValueError(f"Unknown condition pattern: {text[:120]}...")


# ── helpers ──────────────────────────────────────────────────────────

def _parse_bb_list(raw: str) -> list[str]:
    parts = re.split(r',\s*BB:', raw)
    result = [parts[0].strip()]
    for p in parts[1:]:
        result.append('BB:' + p.strip())
    return result


def _parse_qid_list(raw: str) -> list[dict]:
    entries = re.split(r',\s*(?=\()', raw)
    result = []
    for entry in entries:
        entry = entry.strip()
        m = re.match(r'\((\d+)\)\s*(.+)', entry)
        if m:
            result.append({'qid': int(m.group(1)), 'label': m.group(2).strip()})
    return result


def _parse_csv(raw: str) -> list[str]:
    return [v.strip() for v in raw.split(',') if v.strip()]


# ── pattern registry ─────────────────────────────────────────────────

_PATTERNS: list[tuple[str, callable]] = []


def _register(pattern: str):
    def decorator(fn):
        _PATTERNS.append((pattern, fn))
        return fn
    return decorator


# BB predicates
@_register(r'when an event matches all of the following (BB:.+)')
def _h_match_all_bb(m):
    return {'op': 'match_all_bb', 'bb': _parse_bb_list(m.group(1))}


@_register(r'NOT when an event matches any of the following (BB:.+)')
def _h_match_none_bb(m):
    return {'op': 'match_none_bb', 'bb': _parse_bb_list(m.group(1))}


@_register(r'when an event matches any of the following (BB:.+)')
def _h_match_any_bb(m):
    return {'op': 'match_any_bb', 'bb': _parse_bb_list(m.group(1))}


# Field predicates (put field_not_one_of before field_one_of for safety)
@_register(r'NOT when the source IP is one of the following (.+)')
def _h_not_source_ip(m):
    return {'op': 'field_not_one_of', 'field': 'source IP', 'values': _parse_csv(m.group(1))}


@_register(r'NOT when the destination IP is one of the following (.+)')
def _h_not_dest_ip(m):
    return {'op': 'field_not_one_of', 'field': 'destination IP', 'values': _parse_csv(m.group(1))}


@_register(r'when the source IP is one of the following (.+)')
def _h_source_ip(m):
    return {'op': 'field_one_of', 'field': 'source IP', 'values': _parse_csv(m.group(1))}


@_register(r'when the destination IP is one of the following (.+)')
def _h_dest_ip(m):
    return {'op': 'field_one_of', 'field': 'destination IP', 'values': _parse_csv(m.group(1))}


@_register(r'NOT when either the source or destination IP is one of the following (.+)')
def _h_either_ip_not(m):
    return {
        'op': 'either_field_not_one_of',
        'fields': ['source IP', 'destination IP'],
        'values': _parse_csv(m.group(1)),
    }


# Event-level predicates
@_register(r'when the event QID is one of the following (.+)')
def _h_event_qid(m):
    return {'op': 'field_one_of', 'field': 'event QID', 'values': _parse_qid_list(m.group(1))}


@_register(r'when the event context is (.+)')
def _h_event_context(m):
    return {'op': 'field_one_of', 'field': 'event context', 'values': _parse_csv(m.group(1))}


@_register(r'when the event\(s\) were detected by one or more of (.+)')
def _h_log_source(m):
    return {'op': 'log_source_is', 'source': m.group(1).strip()}


@_register(r'when the event category for the event is one of the following (.+)')
def _h_event_category(m):
    return {'op': 'event_category_is', 'category': m.group(1).strip()}


# Network predicates
@_register(r'NOT when the source network is (.+)')
def _h_source_network_not(m):
    return {'op': 'source_network_not', 'network': m.group(1).strip()}


# Reference set predicates (put name-match before general refset)
@_register(r'when any of (Reference Set Name \(custom\)) match (.+)')
def _h_refset_name_match(m):
    return {'op': 'field_one_of', 'field': m.group(1).strip(), 'values': [m.group(2).strip()]}


@_register(r'NOT when any of (.+?) are contained in any of \(([^)]+)\) (.+)')
def _h_not_in_refset(m):
    return {
        'op': 'field_not_in_refset',
        'field': m.group(1).strip(),
        'refset': {'scope': m.group(2).strip(), 'name': m.group(3).strip()},
    }


@_register(r'when any of (.+?) are contained in any of \(([^)]+)\) (.+)')
def _h_in_refset(m):
    return {
        'op': 'field_in_refset',
        'field': m.group(1).strip(),
        'refset': {'scope': m.group(2).strip(), 'name': m.group(3).strip()},
    }


# Regex pattern (Username match) — text contains literal backslash-bracket: \[value]
@_register(r'when the event matches (Username) is any of \\(.+)')
def _h_username_regex(m):
    return {'op': 'field_matches', 'field': m.group(1).strip(), 'pattern': m.group(2).strip()}


# Sequence (must register before simpler BB patterns)
_SEQ_RE = (
    r'when a subset of at least (\d+) of these (.+?), in order, '
    r'with the same (.+?) followed by a subset of at least (\d+) '
    r'of these (.+?) in order from the same (.+?) from the previous '
    r'sequence, within (\d+) minutes'
)


@_register(_SEQ_RE)
def _h_sequence(m):
    return {
        'op': 'sequence',
        'steps': [
            {'count': int(m.group(1)), 'bb': _parse_bb_list(m.group(2))},
            {'count': int(m.group(4)), 'bb': _parse_bb_list(m.group(5))},
        ],
        'window_min': int(m.group(7)),
        'same_field': m.group(3).strip(),
    }


# Threshold with distinct
_THR_DIST_RE = (
    r'when (BB:.+?) match at least (\d+) times with the same (.+?) '
    r'and different (.+?) in (\d+) minutes'
)


@_register(_THR_DIST_RE)
def _h_threshold_distinct(m):
    return {
        'op': 'threshold',
        'bb': m.group(1).strip(),
        'count': int(m.group(2)),
        'window_min': int(m.group(5)),
        'group_by': _parse_csv(m.group(3)),
        'distinct': _parse_csv(m.group(4)),
    }


# Threshold simple
@_register(r'when (BB:.+?) match at least (\d+) times with the same (.+?) in (\d+) minutes')
def _h_threshold_simple(m):
    return {
        'op': 'threshold',
        'bb': m.group(1).strip(),
        'count': int(m.group(2)),
        'window_min': int(m.group(4)),
        'group_by': _parse_csv(m.group(3)),
        'distinct': [],
    }


# Time-based BB correlation (Spring rule style)
@_register(
    r'when (BB:.+?) match at least (\d+) times in (\d+) minutes '
    r'after any of (BB:.+?) match'
)
def _h_time_correlation(m):
    return {
        'op': 'threshold',
        'bb': m.group(4).strip(),       # the "after any of" BB
        'count': int(m.group(2)),
        'window_min': int(m.group(3)),
        'group_by': [],
        'distinct': [],
        'trigger_bb': m.group(1).strip(),  # the BB that fires at least N times
    }


# ═══════════════════════════════════════════════════════════════════════
#  EMITTER (structured → QRadar text)
# ═══════════════════════════════════════════════════════════════════════

def emit_qradar(structured: dict) -> str:
    """Convert structured detection dict back to QRadar test text."""
    name = structured['name']
    scope = structured['scope']
    conds = [_emit_predicate(p) for p in structured['logic']]

    prefix = f"Apply {name} on events which are detected by the {scope}"
    if not conds:
        return prefix
    # Join with canonical line breaks for round-trip readability.
    return prefix + "\n" + "\n".join(f"and {c}" for c in conds)


def _emit_predicate(p: dict) -> str:
    op = p['op']
    emitter = _EMITTERS.get(op)
    if emitter is None:
        raise ValueError(f"No emitter registered for op '{op}'")
    return emitter(p)


def _emit_qid_values(values: list[dict]) -> str:
    return ', '.join(f"({q['qid']}) {q['label']}" for q in values)


def _emit_csv(values: list[str]) -> str:
    return ', '.join(values)


def _emit_threshold(p: dict) -> str:
    if p.get('trigger_bb'):
        return (
            f"when {p['trigger_bb']} match at least {p['count']} times "
            f"in {p['window_min']} minutes after any of {p['bb']} match"
        )
    group_part = ', '.join(p['group_by'])
    if p.get('distinct'):
        distinct_part = ', '.join(p['distinct'])
        return (
            f"when {p['bb']} match at least {p['count']} times "
            f"with the same {group_part} and different {distinct_part} "
            f"in {p['window_min']} minutes"
        )
    return (
        f"when {p['bb']} match at least {p['count']} times "
        f"with the same {group_part} in {p['window_min']} minutes"
    )


def _emit_sequence(p: dict) -> str:
    s0, s1 = p['steps']
    return (
        f"when a subset of at least {s0['count']} of these "
        f"{', '.join(s0['bb'])}, in order, with the same {p['same_field']} "
        f"followed by a subset of at least {s1['count']} of these "
        f"{', '.join(s1['bb'])} in order from the same {p['same_field']} "
        f"from the previous sequence, within {p['window_min']} minutes"
    )


def _emit_field_one_of(p: dict) -> str:
    field = p['field']
    if isinstance(p['values'][0], dict):
        vals = _emit_qid_values(p['values'])
    else:
        vals = _emit_csv(p['values'])

    if field == 'event context':
        return f"when the event context is {vals}"
    elif field == 'Reference Set Name (custom)':
        return f"when any of Reference Set Name (custom) match {vals}"
    else:
        return f"when the {field} is one of the following {vals}"


_EMITTERS = {
    'match_all_bb': lambda p: (
        f"when an event matches all of the following "
        f"{', '.join(p['bb'])}"
    ),
    'match_any_bb': lambda p: (
        f"when an event matches any of the following "
        f"{', '.join(p['bb'])}"
    ),
    'match_none_bb': lambda p: (
        f"NOT when an event matches any of the following "
        f"{', '.join(p['bb'])}"
    ),
    'field_one_of': _emit_field_one_of,
    'field_not_one_of': lambda p: (
        f"NOT when the {p['field']} is one of the following "
        f"{_emit_csv(p['values'])}"
    ),
    'field_in_refset': lambda p: (
        f"when any of {p['field']} are contained in any of "
        f"({p['refset']['scope']}) {p['refset']['name']}"
    ),
    'field_not_in_refset': lambda p: (
        f"NOT when any of {p['field']} are contained in any of "
        f"({p['refset']['scope']}) {p['refset']['name']}"
    ),
    'either_field_not_one_of': lambda p: (
        f"NOT when either the source or destination IP "
        f"is one of the following {_emit_csv(p['values'])}"
    ),
    'log_source_is': lambda p: (
        f"when the event(s) were detected by one or more of {p['source']}"
    ),
    'event_category_is': lambda p: (
        f"when the event category for the event is one of the following "
        f"{p['category']}"
    ),
    'source_network_not': lambda p: (
        f"NOT when the source network is {p['network']}"
    ),
    'field_matches': lambda p: (
        f"when the event matches {p['field']} is any of "
        f"\\{p['pattern']}"
    ),
    'threshold': _emit_threshold,
    'sequence': _emit_sequence,
}


# ═══════════════════════════════════════════════════════════════════════
#  ROUND-TRIP VALIDATION
# ═══════════════════════════════════════════════════════════════════════

def _normalize(text: str) -> str:
    """Collapse whitespace for semantic comparison."""
    return re.sub(r'\s+', ' ', text).strip()


def check_roundtrip(rules_file: Path) -> int:
    """Parse every test/detection_raw field, emit back, diff. Returns 0 on success.
    If neither test nor detection_raw exists, validates structured detection by
    emit→re-parse round-trip."""
    import copy
    with open(rules_file, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    errors = 0
    checked = 0
    for rule in data.get('detection_rules', []) or []:
        raw = (rule.get('test') or rule.get('detection_raw') or '').strip()

        if raw:
            checked += 1
            try:
                parsed = parse_test(raw)
                emitted = emit_qradar(parsed)
            except (ValueError, KeyError) as exc:
                print(f"FAIL [{rule['id']}]: {exc}", file=sys.stderr)
                errors += 1
                continue

            if _normalize(raw) != _normalize(emitted):
                print(f"MISMATCH [{rule['id']}]:", file=sys.stderr)
                print(f"  ORIG: {raw[:200]}", file=sys.stderr)
                print(f"  EMIT: {emitted[:200]}", file=sys.stderr)
                errors += 1
        else:
            # Validate structured detection by emit→re-parse round-trip
            structured = rule.get('detection')
            if not structured:
                continue
            checked += 1
            try:
                emitted = emit_qradar(structured)
                reparsed = parse_test(emitted)
            except (ValueError, KeyError) as exc:
                print(f"FAIL [{rule['id']}]: structured round-trip: {exc}", file=sys.stderr)
                errors += 1
                continue

            # Compare logic (ignore name/scope which may differ slightly)
            if structured.get('logic') != reparsed.get('logic'):
                print(f"MISMATCH [{rule['id']}]: structured re-parse differs", file=sys.stderr)
                errors += 1

    if errors:
        print(f"\n{errors}/{checked} rule(s) failed round-trip check.", file=sys.stderr)
        return 1

    print(f"All {checked} rules round-trip successfully.")
    return 0


# ═══════════════════════════════════════════════════════════════════════
#  TRANSFORM (migrate file in-place)
# ═══════════════════════════════════════════════════════════════════════

def transform_file(rules_file: Path) -> int:
    """Replace `test` with structured `detection` on every rule."""
    from ruamel.yaml import YAML
    from ruamel.yaml.scalarstring import LiteralScalarString

    bak = rules_file.with_suffix(rules_file.suffix + '.bak')
    shutil.copy2(rules_file, bak)
    print(f"Backed up to {bak}")

    ryml = YAML()
    ryml.preserve_quotes = True
    ryml.width = 120
    ryml.indent(mapping=2, sequence=4, offset=2)

    with open(rules_file, 'r', encoding='utf-8') as f:
        data = ryml.load(f)

    errors = 0
    transformed = 0
    for rule in data.get('detection_rules', []) or []:
        raw_test = (rule.get('test') or '').strip()
        if not raw_test:
            continue
        try:
            parsed = parse_test(raw_test)
            emitted = emit_qradar(parsed)
        except (ValueError, KeyError) as exc:
            print(f"FAIL [{rule['id']}]: {exc}", file=sys.stderr)
            errors += 1
            continue

        if _normalize(raw_test) != _normalize(emitted):
            print(f"SKIP [{rule['id']}]: round-trip mismatch", file=sys.stderr)
            errors += 1
            continue

        # Insert new fields at the position of the old 'test' field
        idx = list(rule.keys()).index('test')
        del rule['test']
        # Insert in reverse order so they appear as detection, detection_raw
        rule.insert(idx, 'detection_raw', LiteralScalarString(raw_test))
        rule.insert(idx, 'detection', parsed)
        transformed += 1

    if errors:
        print(f"\n{errors} rule(s) could not be transformed. Aborting.", file=sys.stderr)
        return 1

    with open(rules_file, 'w', encoding='utf-8') as f:
        ryml.dump(data, f)

    print(f"Transformed {transformed} rules in {rules_file}")
    return 0


def drop_raw_field(rules_file: Path) -> int:
    """Remove `detection_raw` audit fields after verification."""
    from ruamel.yaml import YAML

    ryml = YAML()
    ryml.preserve_quotes = True
    ryml.width = 120
    ryml.indent(mapping=2, sequence=4, offset=2)

    with open(rules_file, 'r', encoding='utf-8') as f:
        data = ryml.load(f)

    for rule in data.get('detection_rules', []) or []:
        if 'detection_raw' in rule:
            del rule['detection_raw']

    with open(rules_file, 'w', encoding='utf-8') as f:
        ryml.dump(data, f)

    print(f"Dropped detection_raw from all rules in {rules_file}")
    return 0


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════

def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    cmd = sys.argv[1]
    filepath = Path(sys.argv[2])

    if cmd == '--check':
        return check_roundtrip(filepath)
    elif cmd == '--transform':
        return transform_file(filepath)
    elif cmd == '--drop-raw':
        return drop_raw_field(filepath)
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
