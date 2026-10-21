"""OWASP Mobile Top 10 (2023) compliance scoring and report generation.

Methodology:
  - Each OWASP category is evaluated through weighted checks.
  - "absent" checks pass when no finding from the mapped rules exists.
  - "evidence" checks pass only when positive security evidence was found
    (e.g. certificate pinning, Keystore/Keychain usage, AEAD ciphers).
  - Compliance % = passed weight / applicable weight per category; the
    overall score is the weighted average across categories. Absence of
    evidence for a protection is scored as failure (defense-in-depth).
"""

import html
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from . import __version__
from .models import (
    OWASP_2016,
    OWASP_2023,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    stable_id,
)

TOOL_NAME = "Mobile App Security Analyzer (masa)"
TOOL_VERSION = __version__

# category -> list of (check_id, check_name, weight, kind, refs)
# kind "absent": refs = rule ids (or id prefixes) whose findings fail it
# kind "evidence": refs = positive-evidence keys that pass it
CHECKS = {
    "M1": [("M1-1", "No hardcoded credentials/secrets", 6, "absent",
            ["SEC-"]),
           ("M1-2", "Secrets not in URL/query strings", 3, "absent",
            ["NET-009"])],
    "M5": [("M5-1", "No cleartext communication", 5, "absent",
            ["NET-001", "NET-002", "NET-003", "NET-007", "NET-011",
             "NET-016"]),
           ("M5-2", "No TLS validation bypass", 6, "absent",
            ["NET-004", "NET-005", "NET-006"]),
           ("M5-3", "Certificate pinning implemented", 4, "evidence",
            ["pinning"]),
           ("M5-4", "No hardcoded raw endpoints", 2, "absent",
            ["NET-008", "NET-010"]),
           ("M5-5", "Safe WebView configuration", 3, "absent",
            ["NET-012", "NET-013", "NET-014"])],
    "M10": [("M10-1", "No weak ciphers/hashes in use", 5, "absent",
             ["CRY-001", "CRY-002", "CRY-003", "CRY-004", "CRY-005",
              "CRY-006", "CRY-007", "CRY-008", "CRY-009", "CRY-010",
              "CRY-011", "CRY-012", "NAT-002", "NAT-004"]),
            ("M10-2", "Authenticated encryption (AEAD) used", 3, "evidence",
             ["aead"]),
            ("M10-3", "Secure random sources", 3, "evidence",
             ["secure_random"]),
            ("M10-4", "Secure key derivation (PBKDF2/scrypt/Argon2)", 2,
             "evidence", ["kdf"]),
            ("M10-5", "Keys protected by platform keystore", 3, "evidence",
             ["keystore", "keychain"])],
    "M9": [("M9-1", "No insecure storage of sensitive data", 5, "absent",
            ["STO-", "LOG-"]),
           ("M9-2", "Encryption at rest / Keystore-Keychain", 4, "evidence",
            ["keystore", "keychain"]),
           ("M9-3", "Encrypted databases (SQLCipher)", 2, "evidence",
            ["sqlcipher"])],
    "M3": [("M3-1", "No exposed components without protection", 4, "absent",
            ["CFG-001", "ATH-001", "ATH-002"]),
           ("M3-2", "Platform biometric/auth mechanisms", 2, "evidence",
            ["biometric"])],
    "M4": [("M4-1", "No SQL injection risk", 4, "absent", ["INP-001"]),
           ("M4-2", "No dangerous WebView bridges / file access", 4, "absent",
            ["INP-003", "NET-012", "NET-013", "NET-014"]),
           ("M4-3", "No path traversal patterns", 2, "absent", ["INP-002"])],
    "M6": [("M6-1", "No PII / credential logging", 4, "absent",
            ["LOG-001", "LOG-002"]),
           ("M6-2", "No device identifier harvesting", 2, "absent",
            ["PRI-001"]),
           ("M6-3", "Consent / privacy mechanisms present", 2, "evidence",
            ["consent", "att_consent"]),
           ("M6-4", "No tracking without consent", 2, "absent",
            ["PRI-003"])],
    "M7": [("M7-1", "Code obfuscation / hardening applied", 3, "evidence",
            ["obfuscation"]),
           ("M7-2", "Not debuggable (release build)", 4, "absent",
            ["CFG-004"]),
           ("M7-3", "Native/binary protections sound", 4, "absent",
            ["NAT-001", "NAT-003", "NAT-006", "NAT-007", "NAT-008",
             "BIN-004"]),
           ("M7-4", "Root/jailbreak detection present", 2, "evidence",
            ["root_detection"])],
    "M8": [("M8-1", "No exported components without permission", 4, "absent",
            ["CFG-001"]),
           ("M8-2", "Permission usage appropriate", 4, "absent",
            ["PERM-001", "PERM-002", "PERM-003", "PERM-004"]),
           ("M8-3", "Backup/export configuration secure", 2, "absent",
            ["CFG-002", "CFG-003"]),
           ("M8-4", "No staging/test configuration shipped", 1, "absent",
            ["CFG-005"])],
    "M2": [("M2-1", "Modern SDK / OS baseline", 3, "absent",
            ["SCP-001", "SCP-004"]),
           ("M2-2", "No legacy / deprecated libraries", 2, "absent",
            ["SCP-002"]),
           ("M2-3", "No dynamic code loading", 2, "absent", ["SCP-003"])],
}

SEVERITY_COLORS = {
    "critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825",
    "low": "#689f38", "info": "#607d8b",
}

# SARIF uses error/warning/note; GitHub's security tab uses the numeric score.
SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                     "low": "2.5", "info": "0.0"}


def _matches(rule_id: str, refs: List[str]) -> bool:
    return any(rule_id == ref or rule_id.startswith(ref) for ref in refs)


def _status_of(check: Tuple[str, str, int, str, List[str]], result: Dict[str, Any]) -> Tuple[str, str]:
    check_id, _name, _weight, kind, refs = check
    if kind == "evidence":
        keys = result["positives"]
        for ref in refs:
            if ref in keys:
                return ("pass", keys[ref].get("evidence", ""))
        return ("fail", "no evidence found")
    fail_findings = [f for f in result["findings"]
                     if _matches(f["id"], refs)]
    if fail_findings:
        return ("fail", "triggered by %s" % fail_findings[0]["id"])
    return ("pass", "no findings")


def score(result: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int]:
    """Compute per-category compliance + overall score from a report dict."""
    categories = []
    total_weight = 0
    passed_weight = 0
    for cid, cname in OWASP_2023.items():
        checks = []
        for check in CHECKS.get(cid, []):
            status, evidence = _status_of(check, result)
            checks.append({"id": check[0], "name": check[1],
                           "weight": check[2], "status": status,
                           "evidence": evidence})
        weight = sum(c["weight"] for c in checks)
        passed = sum(c["weight"] for c in checks if c["status"] == "pass")
        pct = round(passed / weight * 100) if weight else 0
        total_weight += weight
        passed_weight += passed
        categories.append({
            "id": cid, "name": cname,
            "legacy": OWASP_2016.get(cid, ""),
            "compliance": pct, "checks": checks,
            "weight": weight, "passed_weight": passed,
        })
    overall = round(passed_weight / total_weight * 100) if total_weight else 0
    return categories, overall


def grade_for(pct: int) -> Tuple[str, str]:
    if pct >= 90:
        return "A", "Excellent - strong security posture for most risk areas"
    if pct >= 75:
        return "B", "Good - some controls need attention"
    if pct >= 60:
        return "C", "Fair - significant gaps should be remediated"
    if pct >= 45:
        return "D", "Poor - major security deficiencies"
    return "F", "Critical - immediate remediation required"


def build_report(result: Any, meta: Optional[Dict[str, Any]] = None, rules_ref: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Serialize an AnalysisResult into the full report dictionary."""
    meta = meta or {}
    findings = [f.to_dict() for f in result.findings]
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]),
                                 f["id"], f["file"] or ""))
    positives = [p.to_dict() for p in result.positives]
    categories, overall = score({
        "findings": findings,
        "positives": {p["key"]: p for p in positives},
    })
    grade, grade_desc = grade_for(overall)

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        severity_counts[f["severity"]] += 1
    risk_score = sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings)

    top = []
    for f in findings:
        if len(top) >= 5:
            break
        top.append({"id": f["id"], "title": f["title"],
                    "severity": f["severity"], "owasp": f["owasp"],
                    "file": f["file"], "line": f.get("line")})

    by_category = []
    for cid, cname in OWASP_2023.items():
        cat_findings = [f for f in findings if f["owasp"] == cid]
        by_category.append({
            "id": cid, "name": cname,
            "legacy": OWASP_2016.get(cid, ""),
            "findings": cat_findings,
        })

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": {
            "platform": result.platform,
            "name": result.app_name,
            "path": meta.get("path", ""),
            "sha256": meta.get("sha256", ""),
        },
        "summary": result.summary,
        "grade": grade,
        "grade_description": grade_desc,
        "overall_compliance": overall,
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "top_findings": top,
        "categories": categories,
        "by_category": by_category,
        "findings": findings,
        "positives": positives,
        "notes": result.notes,
        "binaries": result.binaries,
        "permission_audit": result.permission_audit,
        "rules_reference": rules_ref or [],
    }


# ------------------------------------------------------------------ outputs

def _fmt_sev_count(data):
    return ", ".join("%s: %d" % (s, data["severity_counts"][s])
                     for s in SEVERITY_ORDER)


def console_summary(data):
    lines = []
    t = data["target"]
    lines.append("=" * 70)
    lines.append("%s v%s" % (data["tool"], data["version"]))
    lines.append("Target : %s (%s)  %s" % (t.get("name"), t.get("platform"),
                                           t.get("path")))
    lines.append("SHA256 : %s" % (t.get("sha256") or "-"))
    lines.append("-" * 70)
    lines.append("Findings: %s" % _fmt_sev_count(data))
    lines.append("Risk score: %d | OWASP compliance: %d%% | Grade: %s"
                 % (data["risk_score"], data["overall_compliance"],
                    data["grade"]))
    lines.append("-" * 70)
    for cat in data["categories"]:
        bar = "#" * (cat["compliance"] // 10) + "." * (10 - cat["compliance"] // 10)
        lines.append("  %s %s %3d%% [%s]" % (cat["id"], cat["name"][:44].ljust(44),
                                             cat["compliance"], bar))
    lines.append("-" * 70)
    for f in data["top_findings"]:
        loc = f.get("file") or "?"
        line = f.get("line")
        if line is not None:
            loc += ":%s" % line
        lines.append("  [%s] %s %s  %s" %
                     (f["severity"].upper().ljust(8), f["id"], f["title"],
                      loc))
    return "\n".join(lines)


def write_json(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def build_sarif(data):
    """Build a SARIF 2.1.0 document for GitHub code scanning."""
    refs = {r["id"]: r for r in data.get("rules_reference", [])}
    rule_ids = []
    rule_index = {}
    severities = {}
    for finding in data["findings"]:
        rid = finding["id"]
        if rid not in rule_index:
            rule_index[rid] = len(rule_ids)
            rule_ids.append(rid)
            severities[rid] = finding["severity"]

    rules = []
    for rid in rule_ids:
        meta = refs.get(rid, {})
        severity = meta.get("severity") or severities[rid]
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": meta.get("title", rid)},
            "fullDescription": {"text": meta.get("description", "")},
            "help": {"text": meta.get("remediation", "")},
            "defaultConfiguration": {
                "level": SARIF_LEVELS.get(severity, "note")
            },
            "properties": {
                "security-severity": SECURITY_SEVERITY.get(severity, "0.0"),
                "tags": ["security", meta.get("owasp", "")],
            },
        })

    results = []
    for finding in data["findings"]:
        rid = finding["id"]
        path = finding.get("file") or ""
        line = finding.get("line")
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": SARIF_LEVELS.get(finding["severity"], "note"),
            "message": {
                "text": "%s [%s]" % (finding["title"], finding["owasp"])
            },
            "partialFingerprints": {
                "masa/v1": stable_id("%s|%s|%s|%s" % (
                    rid, path, line or 0, finding.get("match") or ""))
            },
            "properties": {
                "severity": finding["severity"],
                "owasp": finding["owasp"],
                "evidenceType": finding.get("evidence_type", ""),
            },
        }
        if path:
            location = {
                "artifactLocation": {
                    "uri": quote(path.replace("\\", "/"), safe="/")
                }
            }
            if line and finding.get("evidence_type") in ("code", "manifest",
                                                          "config"):
                location["region"] = {"startLine": int(line)}
            result["locations"] = [{"physicalLocation": location}]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "masa",
                    "informationUri": "https://github.com/N4khlA/"
                                      "MobileApp_SecAnalyzer",
                    "version": data.get("version", TOOL_VERSION),
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{"executionSuccessful": True}],
            "properties": {"target": data.get("target", {})},
        }],
    }


def write_sarif(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(data), fh, indent=2, default=str)


def write_markdown(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_md(data))


def _md(data):
    t = data["target"]
    pkg = (data["summary"] or {}).get("package") or \
        (data["summary"] or {}).get("bundle_id") or ""
    out = ["# Mobile App Security Analysis Report",
           "",
           "**Tool:** %s v%s  \n**Timestamp:** %s  " %
           (data["tool"], data["version"], data["timestamp"]),
           "**Target:** %s (%s)  " % (t.get("name"), t.get("platform")),
           "**Package/Bundle:** %s  " % pkg,
           "**SHA-256:** `%s`  " % (t.get("sha256") or "-"),
           "",
           "## Executive Summary",
           "",
           "| Metric | Value |",
           "|---|---|",
           "| Overall OWASP compliance | %d%% |" % data["overall_compliance"],
           "| Grade | %s - %s |" % (data["grade"], data["grade_description"]),
           "| Risk score | %d |" % data["risk_score"],
           "| Findings | %s |" % _fmt_sev_count(data),
           "",
           "### Top Findings",
           ""]
    for f in data["top_findings"]:
        loc = "%s:%s" % (f.get("file") or "?", f.get("line")) \
            if f.get("line") is not None else (f.get("file") or "?")
        out.append("- **%s** [%s] `%s` - %s (%s)" %
                   (f["title"], f["severity"].upper(), f["id"], loc,
                    f["owasp"]))
    out += ["", "## Compliance Scoring (OWASP Mobile Top 10 2023)", ""]
    out.append("| ID | Category | Compliance | Failing checks |")
    out.append("|---|---|---:|---|")
    for cat in data["categories"]:
        fails = [c["id"] for c in cat["checks"] if c["status"] == "fail"]
        out.append("| %s | %s | %d%% | %s |" %
                   (cat["id"], cat["name"], cat["compliance"],
                    ", ".join(fails) if fails else "-"))
    out += ["", "## Detailed Findings", ""]
    for cat in data["by_category"]:
        if not cat["findings"]:
            continue
        out.append("### %s - %s" % (cat["id"], cat["name"]))
        out.append("*(legacy 2016: %s)*" % cat["legacy"])
        out.append("")
        for f in cat["findings"]:
            out.append("#### %s `%s` [%s]" %
                       (f["title"], f["id"], f["severity"].upper()))
            loc = f.get("file") or "?"
            if f.get("line") is not None:
                loc += ":%s" % f["line"]
            out.append("- **Location:** %s  " % loc)
            out.append("- **OWASP:** %s (2023), %s (2016)" %
                       (f["owasp"], f.get("legacy_owasp") or "-"))
            if f.get("match"):
                out.append("- **Evidence:** `%s`  " % f["match"])
            out.append("- **Description:** %s  " % f["description"])
            if f.get("context"):
                out.append("- **Proof of concept (code):**")
                out.append("")
                out.append("```")
                out.append(f["context"])
                out.append("```")
            out.append("- **Remediation:** %s  " % f["remediation"])
            out.append("")
    out += ["", "## Positive Security Evidence", ""]
    if data["positives"]:
        for p in data["positives"]:
            out.append("- **%s:** %s" % (p["key"], p["evidence"]))
    else:
        out.append("_No positive security controls were observed._")
    out += ["", "## Methodology & Limitations", "",
            "This is a **static analysis** assessment. It inspects the "
            "manifest/Info.plist, resources, (decompiled) code, dex string "
            "tables, and native binaries for vulnerability patterns. Static "
            "analysis cannot observe runtime behavior:",
            "",
            "- Authenticated flows, session handling and business logic "
            "must be validated with dynamic analysis (instrumentation, "
            "interception, debugging).",
            "- Absence of a finding is not proof of security - it means no "
            "pattern was detected.",
            "- Binary-only analysis (no decompiler on PATH) recovers "
            "strings, not control flow, so logic-level issues may be "
            "missed.",
            "",
            "### Comparison to commercial tools",
            "",
            "| Capability | This tool | Checkmarx/Veracode/Fortify (SAST) | "
            "MobSF |",
            "|---|---|---|---|",
            "| Hardcoded secrets | Yes (regex + string tables) | Yes (more "
            "advanced taint) | Yes |",
            "| Data-flow / taint analysis | Partial (pattern) | Yes | "
            "Limited |",
            "| Dynamic analysis | No | No (separate products) | Yes |",
            "| OWASP Mobile Top 10 scoring | Yes (2023 + 2016 mapping) | "
            "Varies | Yes |",
            "| False positives | Fewer, less coverage | Fewer, heavier "
            "configuration | Medium |",
            "",
            "Commercial SAST tools add taint/data-flow analysis, deeper "
            "semantic understanding and fewer false positives, at the cost "
            "of licensing and setup. This tool trades coverage for "
            "transparency and zero dependencies.",
            ""]
    if data["notes"]:
        out += ["", "## Analysis Notes", ""]
        for n in data["notes"]:
            out.append("- %s" % n)
    return "\n".join(out)


def _esc(s):
    return html.escape(str(s))


def write_html(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_html(data))


def _html(data):
    t = data["target"]
    rows = []
    for cat in data["categories"]:
        pct = cat["compliance"]
        color = "#4caf50" if pct >= 75 else ("#ff9800" if pct >= 50 else "#e53935")
        fails = [c["id"] for c in cat["checks"] if c["status"] == "fail"]
        rows.append("""
        <tr>
          <td><b>%s</b></td>
          <td>%s<br><small>legacy 2016: %s</small></td>
          <td><div class="bar"><div class="barfill" style="width:%d%%;background:%s"></div></div></td>
          <td><b>%d%%</b></td>
          <td>%s</td>
        </tr>""" % (cat["id"], _esc(cat["name"]), _esc(cat["legacy"]), pct,
                    color, pct, _esc(", ".join(fails) if fails else "-")))

    finding_blocks = []
    for cat in data["by_category"]:
        if not cat["findings"]:
            continue
        blocks = []
        for f in cat["findings"]:
            loc = f.get("file") or "?"
            if f.get("line") is not None:
                loc += ":%s" % f["line"]
            context = ""
            if f.get("context"):
                context = ("<div class='poc'><div class='poctitle'>Proof of "
                           "concept (vulnerable code)</div><pre>%s</pre></div>"
                           % _esc(f["context"]))
            match = ("<code>%s</code>" % _esc(f["match"])) if f.get("match") \
                else ""
            blocks.append("""
          <div class="finding">
            <h4 style="color:%s">%s <span class="badge">%s</span> <code>%s</code></h4>
            <p class="loc"><b>Location:</b> %s &nbsp; <b>OWASP:</b> %s (2023)
            / %s (2016) &nbsp; <b>Type:</b> %s</p>
            <p>%s</p>
            <p>%s</p>
            %s
            <p class="rem"><b>Remediation:</b> %s</p>
          </div>""" % (SEVERITY_COLORS[f["severity"]], _esc(f["title"]),
                       f["severity"].upper(), _esc(f["id"]), _esc(loc),
                       f["owasp"], f.get("legacy_owasp") or "-",
                       f.get("evidence_type", ""), match,
                       _esc(f["description"]), context, _esc(f["remediation"])))
        finding_blocks.append("""
      <section>
        <h3>%s - %s</h3>
        <p class="sub">(legacy 2016: %s)</p>
        %s
      </section>""" % (cat["id"], _esc(cat["name"]), _esc(cat["legacy"]),
                       "\n".join(blocks)))

    positives = "".join(
        "<li><b>%s:</b> <code>%s</code></li>" % (_esc(p["key"]),
                                                 _esc(p["evidence"]))
        for p in data["positives"]) or "<li><i>None observed.</i></li>"

    notes = "".join("<li>%s</li>" % _esc(n) for n in data["notes"]) or \
        "<li><i>None.</i></li>"

    top = "".join(
        "<tr><td style='color:%s'><b>%s</b></td><td>%s</td><td><code>%s</code>"
        "</td><td>%s</td></tr>" %
        (SEVERITY_COLORS[f["severity"]], f["severity"].upper(), _esc(f["title"]),
         _esc(f["id"]), _esc("%s:%s" % (f.get("file"), f.get("line"))
                             if f.get("line") is not None else f.get("file")))
        for f in data["top_findings"])

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Mobile App Security Analysis - %s</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f6f8;color:#212121}
 .wrap{max-width:1000px;margin:0 auto;padding:24px}
 header{background:#263238;color:#fff;padding:24px;border-radius:8px}
 header h1{margin:0 0 6px;font-size:22px}
 .meta{opacity:.85;font-size:13px}
 .gradebox{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}
 .card{background:#fff;border-radius:8px;padding:16px;flex:1;min-width:180px;
      box-shadow:0 1px 3px rgba(0,0,0,.15)}
 .card .big{font-size:30px;font-weight:700}
 .bar{background:#eceff1;border-radius:4px;height:14px;width:160px;overflow:hidden}
 .barfill{height:100%%}
 table{width:100%%;border-collapse:collapse;background:#fff;border-radius:8px;
      overflow:hidden}
 th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #eceff1;font-size:14px}
 th{background:#37474f;color:#fff}
 section{background:#fff;border-radius:8px;padding:18px 20px;margin:20px 0;
        box-shadow:0 1px 3px rgba(0,0,0,.15)}
 h3{margin-top:0}
 .finding{border-left:4px solid #cfd8dc;padding:6px 14px;margin:14px 0}
 .badge{background:#eceff1;padding:2px 8px;border-radius:10px;font-size:12px}
 .loc{color:#546e7a;font-size:13px}
 .poc{background:#1e272e;color:#7ec699;border-radius:6px;padding:10px 14px;margin:8px 0}
 .poctitle{color:#8a97a1;font-size:11px;text-transform:uppercase;margin-bottom:6px}
 .poc pre{margin:0;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12.5px}
 .rem{color:#33691e;font-size:13.5px}
 code{background:#eceff1;padding:1px 5px;border-radius:4px;font-size:12.5px}
 .sub{color:#607d8b;font-size:13px}
 .sev-table td{vertical-align:middle}
 footer{color:#90a4ae;font-size:12px;text-align:center;margin:24px 0}
</style></head><body><div class="wrap">
<header>
 <h1>Mobile App Security Analysis Report</h1>
 <div class="meta">%s v%s &mdash; %s<br>
 Target: <b>%s</b> (%s)<br>
 SHA-256: <code>%s</code></div>
</header>
<div class="gradebox">
 <div class="card"><div class="big" style="color:%s">%s</div>Overall grade<br>
  <small>%s</small></div>
 <div class="card"><div class="big">%d%%</div>OWASP compliance</div>
 <div class="card"><div class="big">%d</div>Risk score</div>
 <div class="card"><div class="big" style="font-size:20px">%s</div>Findings by severity</div>
</div>
<section><h3>Executive Summary</h3>
 <p>%d findings were identified across %d OWASP categories. %s</p>
 <table><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Location</th></tr>%s</table>
</section>
<section><h3>OWASP Mobile Top 10 Compliance Scoring (2023)</h3>
 <table>
 <tr><th>ID</th><th>Category</th><th>Compliance</th><th>%%</th><th>Failed checks</th></tr>
 %s
 </table>
 <p class="sub">Scoring: weighted checks per category; absence of evidence for a
 protection control counts as failure. Legacy 2016 category names are listed
 for reference.</p>
</section>
%s
<section><h3>Positive Security Evidence</h3><ul>%s</ul></section>
<section><h3>Analysis Notes</h3><ul>%s</ul></section>
<section><h3>Methodology &amp; Limitations</h3>
 <p>Static analysis of the manifest, resources, code, dex string tables and
 native binaries. It cannot observe runtime behavior: authentication flows,
 session handling and logic bugs require dynamic analysis. Absence of a
 finding is not proof of security. Commercial SAST tools (Checkmarx,
 Veracode, Fortify) add taint/data-flow analysis and semantic understanding;
 this tool trades coverage for transparency and zero dependencies.</p>
</section>
<footer>Generated by %s v%s &mdash; for authorized security assessments only</footer>
</div></body></html>""" % (
        _esc(t.get("name") or "app"), data["tool"], data["version"],
        data["timestamp"], _esc(t.get("name") or "?"), t.get("platform"),
        _esc(t.get("sha256") or "-"), SEVERITY_COLORS["critical"],
        data["grade"], _esc(data["grade_description"]),
        data["overall_compliance"], data["risk_score"],
        _fmt_sev_count(data), len(data["findings"]),
        len(data["categories"]), _esc(data["grade_description"]), top,
        "\n".join(rows), "\n".join(finding_blocks), positives, notes,
        data["tool"], data["version"])
