"""Command-line interface for the Mobile App Security Analyzer."""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Union

from . import __version__
from .apk import analyze_apk
from .ipa import analyze_ipa
from .report import (build_report, console_summary, write_html, write_json,
                     write_markdown)
from .rules import ALL_RULES, rules_for_category


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_platform(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".apk"):
        return "android"
    if lower.endswith(".ipa") or ".app" in lower:
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
    here = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(os.path.dirname(here), "samples")
    sys.path.insert(0, sample_dir)
    try:
        from make_samples import build_all
    except ImportError as exc:
        print("error: samples builder not found (%s)" % exc, file=sys.stderr)
        return 1
    out = args.outdir or os.path.join(sample_dir, "out")
    apk_path, ipa_path = build_all(out)
    print("== Vulnerable Android sample ==")
    r1 = cmd_analyze(argparse.Namespace(
        input=apk_path, outdir=os.path.join(out, "reports"),
        no_decompile=True))
    print("\n== Vulnerable iOS sample ==")
    r2 = cmd_analyze(argparse.Namespace(
        input=ipa_path, outdir=os.path.join(out, "reports"),
        no_decompile=True))
    print("\nDemo complete. Sample fixtures and reports are in %s" %
          os.path.abspath(out))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> Union[int, Dict[str, Any]]:
    parser = argparse.ArgumentParser(
        prog="masa",
        description="Mobile App Security Analyzer - static security "
                    "assessment of Android APKs and iOS IPAs with OWASP "
                    "Mobile Top 10 compliance reporting.")
    sub = parser.add_subparsers(dest="command")

    pa = sub.add_parser("analyze", help="analyze an APK, IPA or app directory")
    pa.add_argument("input", help="path to .apk, .ipa, Android project or "
                                  ".app bundle")
    pa.add_argument("-o", "--outdir", help="directory for report files "
                                           "(json/md/html)")
    pa.add_argument("--no-decompile", action="store_true",
                    help="skip apktool/jadx decompilation even if installed")
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
        return res if isinstance(res, int) else 0
    except (ValueError, OSError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

