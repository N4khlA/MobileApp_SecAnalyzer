"""Suppressions from a config file, and baseline comparison.

A config file (``.masa.toml``, or ``.masa.json`` on any Python) accepts known
findings with a reason:

    [[ignore]]
    rule = "SEC-006"              # optional: omit to match every rule
    path = "res/values/*.xml"     # optional: glob ("*" crosses "/")
    reason = "public demo key"    # required

A baseline is an earlier JSON report. Findings whose fingerprint appears in it
are "known": they stay in the report but no longer fail the gate.
"""

import fnmatch
import json
import os
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import Finding

CONFIG_NAMES = (".masa.toml", ".masa.json")


def find_config(start: Optional[str] = None) -> Optional[str]:
    """Return the first config file in ``start`` (default: the cwd)."""
    base = start or os.getcwd()
    for name in CONFIG_NAMES:
        path = os.path.join(base, name)
        if os.path.isfile(path):
            return path
    return None


def load_config(path: str) -> Dict[str, Any]:
    """Read and validate a config file. Raises ValueError on bad content."""
    if path.endswith(".toml"):
        try:
            import tomllib
        except ImportError:  # Python 3.10
            raise ValueError("%s: reading TOML needs Python 3.11+; use "
                             ".masa.json on Python 3.10" % path) from None
        with open(path, "rb") as fh:
            try:
                data = tomllib.load(fh)
            except tomllib.TOMLDecodeError as exc:
                raise ValueError("%s: %s" % (path, exc)) from None
    else:
        with open(path, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError("%s: %s" % (path, exc)) from None
    if not isinstance(data, dict):
        raise ValueError("%s: expected a table/object at the top level" % path)
    ignores = data.get("ignore", [])
    if not isinstance(ignores, list):
        raise ValueError("%s: 'ignore' must be a list of entries" % path)
    for i, entry in enumerate(ignores, 1):
        where = "%s: ignore entry %d" % (path, i)
        if not isinstance(entry, dict):
            raise ValueError("%s must be a table/object" % where)
        unknown = set(entry) - {"rule", "path", "reason"}
        if unknown:
            raise ValueError("%s has unknown key(s): %s" %
                             (where, ", ".join(sorted(unknown))))
        if not entry.get("rule") and not entry.get("path"):
            raise ValueError("%s needs a 'rule', a 'path' or both" % where)
        if not str(entry.get("reason") or "").strip():
            raise ValueError("%s needs a 'reason'" % where)
    return {"path": path, "ignore": ignores}


def apply_ignores(findings: Iterable[Finding],
                  ignores: List[Dict[str, Any]]) -> int:
    """Mark findings matched by a config entry as suppressed. Inline
    suppressions win. Returns how many findings were newly suppressed."""
    count = 0
    for f in findings:
        if f.suppression:
            continue
        for entry in ignores:
            rule = entry.get("rule")
            path = entry.get("path")
            if rule and rule != f.rule.id:
                continue
            if path and not fnmatch.fnmatchcase(
                    (f.file or "").replace("\\", "/"), path):
                continue
            f.suppression = {"kind": "external",
                             "justification": str(entry["reason"]).strip()}
            count += 1
            break
    return count


def load_baseline(path: str) -> Counter:
    """Fingerprints in an earlier masa JSON report, counted, so two identical
    findings in the baseline excuse at most two now."""
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError("baseline %s: %s" % (path, exc)) from None
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError("baseline %s is not a masa JSON report" % path)
    prints: Counter = Counter()
    for key in ("findings", "baselined", "suppressed"):
        for f in data.get(key) or []:
            if "fingerprint" not in f:
                raise ValueError("baseline %s was made by masa < 1.3; "
                                 "regenerate it" % path)
            prints[f["fingerprint"]] += 1
    return prints


def split(findings: List[Dict[str, Any]], baseline: Optional[Counter]
          ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]],
                     List[Dict[str, Any]]]:
    """Return (new/active, known-from-baseline, suppressed) finding dicts."""
    remaining = Counter(baseline) if baseline else Counter()
    active, known, suppressed = [], [], []
    for f in findings:
        if f.get("suppression"):
            suppressed.append(f)
        elif remaining[f["fingerprint"]] > 0:
            remaining[f["fingerprint"]] -= 1
            known.append(f)
        else:
            active.append(f)
    return active, known, suppressed
