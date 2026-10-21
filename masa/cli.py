"""Command-line interface for the Mobile App Security Analyzer."""

import argparse
import hashlib
import os
import sys
from typing import Any, Dict, Optional, Sequence

from . import __version__
from .apk import analyze_apk
from .ipa import analyze_ipa
from .models import SEVERITY_ORDER
from .report import (
    build_report,
    console_summary,
    write_html,
    write_json,
    write_markdown,
    write_sarif,
)
from .rules import ALL_RULES, rules_for_category


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_platform(path: str) -> str:
    base = os.path.basename(os.path.normpath(path)).lower()
    if base.endswith(".apk"):
        return "android"
    if base.endswith(".ipa") or base.endswith(".app"):
        return "ios"
    if os.path.isdir(path):
        for name in os.listdir(path):
            low = name.lower()
            if low == "androidmanifest.xml":
                return "android"
            if low.endswith(".app") or low == "info.plist":
                return "ios"
        for dirpath, _d, fns in os.walk(path):
            for fn in fns:
                if fn.lower() == "androidmanifest.xml":
                    return "android"
                if fn.lower() == "info.plist":
                    return "ios"
    raise ValueError("cannot detect platform for %r (expected .apk, .ipa, "
                     "an Android project dir or an iOS .app bundle)" % path)


def cmd_analyze(args: argparse.Namespace) -> Dict[str, Any]:
    platform = detect_platform(args.input)
    if platform == "android":
        result = analyze_apk(args.input, use_decompiler=not args.no_decompile)
    else:
        result = analyze_ipa(args.input)
    meta: Dict[str, Any] = {"path": os.path.abspath(args.input)}
    try:
        meta["sha256"] = _sha256(args.input)
    except OSError:
        meta["sha256"] = None
    rules_ref = [r.to_dict() for r in ALL_RULES]
    report = build_report(result, meta, rules_ref)
    print(console_summary(report))
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        base = os.path.splitext(os.path.basename(args.input))[0]
        write_json(report, os.path.join(args.outdir, base + ".report.json"))
        write_markdown(report, os.path.join(args.outdir, base + ".report.md"))
        write_html(report, os.path.join(args.outdir, base + ".report.html"))
        print("\nReports written to %s" % os.path.abspath(args.outdir))
    if getattr(args, "sarif", None):
        sarif_path = os.path.abspath(args.sarif)
        os.makedirs(os.path.dirname(sarif_path), exist_ok=True)
        write_sarif(report, sarif_path)
        print("\nSARIF written to %s" % sarif_path)
    fail_on = getattr(args, "fail_on", "none")
    if fail_on and fail_on != "none":
        limit = SEVERITY_ORDER.index(fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) <= limit
               for f in report["findings"]):
            args.exit_code = 2
    return report


def cmd_rules(args: argparse.Namespace) -> int:
    rules = ALL_RULES
    if args.category:
        rules = rules_for_category(args.category)
    for r in rules:
        print("%-10s %-8s %-5s %s" % (r.id, r.severity, r.owasp, r.title))
    print("\n%d rules (category filter: %s)" % (len(rules),
                                                args.category or "all"))
    print("OWASP Mobile Top 10 2023 categories: M1-M10")
    print("Legacy (2016) mapping is stored per rule.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Build the vulnerable sample fixtures and analyze them end-to-end."""
    from .samples import build_all

    out = args.outdir or os.path.join(os.getcwd(), "masa-demo")
    apk_path, ipa_path = build_all(out)
    print("== Vulnerable Android sample ==")
    cmd_analyze(argparse.Namespace(
        input=apk_path, outdir=os.path.join(out, "reports"),
        no_decompile=True))
    print("\n== Vulnerable iOS sample ==")
    cmd_analyze(argparse.Namespace(
        input=ipa_path, outdir=os.path.join(out, "reports"),
        no_decompile=True))
    print("\nDemo complete. Sample fixtures and reports are in %s" %
          os.path.abspath(out))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="masa",
        description="Mobile App Security Analyzer - static security "
                    "assessment of Android APKs and iOS IPAs with OWASP "
                    "Mobile Top 10 compliance reporting.")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command")

    pa = sub.add_parser("analyze", help="analyze an APK, IPA or app directory")
    pa.add_argument("input", help="path to .apk, .ipa, Android project or "
                                  ".app bundle")
    pa.add_argument("-o", "--outdir", help="directory for report files "
                                           "(json/md/html)")
    pa.add_argument("--no-decompile", action="store_true",
                    help="skip apktool/jadx decompilation even if installed")
    pa.add_argument("--sarif", metavar="PATH",
                    help="write a SARIF 2.1.0 report for CI/code scanning")
    pa.add_argument("--fail-on", choices=SEVERITY_ORDER + ["none"],
                    default="none", metavar="LEVEL",
                    help="exit 2 when a finding at or above LEVEL exists "
                         "(critical, high, medium, low, info; default: none)")
    pa.set_defaults(func=cmd_analyze)

    pr = sub.add_parser("rules", help="list detection rules")
    pr.add_argument("--category", help="filter by category "
                                       "(secrets/crypto/storage/network/...)")
    pr.set_defaults(func=cmd_rules)

    pd = sub.add_parser("demo", help="build vulnerable sample APK/IPA and "
                                     "analyze them")
    pd.add_argument("-o", "--outdir", help="output directory for fixtures")
    pd.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    try:
        res = args.func(args)
        if isinstance(res, int):
            return res
        return getattr(args, "exit_code", 0)
    except (ValueError, OSError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

