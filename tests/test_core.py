"""Tests for the Mobile App Security Analyzer (stdlib unittest)."""

import json
import os
import plistlib
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from masa import (axml, dex as mdex, native,  # noqa: E402
                  plist as bplist, scanner)
from masa.apk import analyze_apk, parse_manifest_bytes  # noqa: E402
from masa.ipa import analyze_ipa  # noqa: E402
from masa.models import mask_secret  # noqa: E402
from masa.report import build_report, console_summary, write_html, \
    write_json, write_markdown  # noqa: E402
from masa.rules import ALL_RULES  # noqa: E402


from masa.samples import (build_apk, build_ipa, make_dex,  # noqa: E402
                          make_elf64, make_macho64, MACHO_PAYLOAD,
                          NATIVE_DATA, INFO_PLIST)


class TestAxml(unittest.TestCase):
    def test_roundtrip(self):
        from masa.samples import build_android_manifest
        data = build_android_manifest()
        self.assertTrue(axml.looks_like_axml(data))
        info = parse_manifest_bytes(data)
        self.assertEqual(info.package, "com.vulnbank.demo")
        self.assertEqual(info.version_code, 1)
        self.assertEqual(info.min_sdk, 21)
        self.assertEqual(info.target_sdk, 26)
        self.assertIn("android.permission.CAMERA", info.permissions)
        self.assertIn("android.permission.INTERNET", info.permissions)
        self.assertEqual(len(info.components), 3)
        main = [c for c in info.components if c["name"] == ".MainActivity"][0]
        self.assertTrue(main["exported"])
        self.assertIn("android.intent.action.MAIN", main["actions"])
        self.assertTrue(info.app.get("debuggable"))
        self.assertTrue(info.app.get("usesCleartextTraffic"))
        self.assertEqual(info.network_config, "@xml/network_security_config")

    def test_plain_xml_manifest(self):
        data = b"""<?xml version="1.0"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.test.app" versionCode="7" versionName="2.1">
          <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
          <uses-permission android:name="android.permission.INTERNET"/>
          <application android:allowBackup="false">
            <activity android:name=".A" android:exported="true">
              <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
              </intent-filter>
            </activity>
            <service android:name=".S"
                     android:permission="android.permission.INTERNET"/>
          </application>
        </manifest>"""
        info = parse_manifest_bytes(data)
        self.assertEqual(info.package, "com.test.app")
        self.assertEqual(info.target_sdk, "33")
        self.assertEqual(info.app.get("allowBackup"), "false")
        self.assertFalse(info.components[1]["exported"])


class TestPlist(unittest.TestCase):
    def test_roundtrip(self):
        data = bplist.dumps(INFO_PLIST)
        parsed = bplist.loads(data)
        self.assertEqual(parsed, INFO_PLIST)

    def test_stdlib_compat(self):
        obj = {"a": 1, "b": "text", "c": True, "d": [1, 2, 3],
               "e": {"nested": "dict", "f": 1.5}, "g": b"\x01\x02"}
        data = bplist.dumps(obj)
        self.assertEqual(plistlib.loads(data), obj)
        self.assertEqual(bplist.loads(plistlib.dumps(
            obj, fmt=plistlib.FMT_BINARY)), obj)


class TestDex(unittest.TestCase):
    def test_roundtrip(self):
        from masa.samples import DEX_STRINGS
        blob = make_dex(DEX_STRINGS)
        self.assertTrue(blob.startswith(b"dex\n"))
        got = mdex.dex_strings(blob)
        self.assertEqual(set(got), set(DEX_STRINGS))

    def test_invalid(self):
        self.assertEqual(mdex.dex_strings(b"not a dex"), [])


class TestBinary(unittest.TestCase):
    def test_elf(self):
        blob = make_elf64(NATIVE_DATA)
        info = native.elf_info(blob)
        self.assertEqual(info["format"], "ELF64")
        self.assertTrue(info["pie"])
        self.assertFalse(info["relro"])
        self.assertTrue(info["exec_stack"])
        self.assertIn("strcpy(dst, src);", info["strings"])

    def test_macho(self):
        blob = make_macho64(MACHO_PAYLOAD)
        info = native.macho_info(blob)
        self.assertEqual(info["format"], "Mach-O64")
        self.assertFalse(info["encrypted"])
        self.assertIn("NSUserDefaults setObject:forKey:password",
                      info["strings"])


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.sc = scanner.Scanner(ALL_RULES)

    def test_secret_detection(self):
        findings = []
        self.sc.scan_text(
            'private static final String KEY = '
            '"sk_live_51AbCdEfGhIjKlMnOpQr";',
            "Test.java", findings)
        ids = [f.rule.id for f in findings]
        self.assertIn("SEC-003", ids)

    def test_asia_aws_key(self):
        findings = []
        self.sc.scan_text('String aws = "ASIAIOSFODNN7EXAMPLE";',
                          "Test.java", findings)
        ids = [f.rule.id for f in findings]
        self.assertIn("SEC-001", ids)

    def test_cleartext_detection(self):
        findings = []
        self.sc.scan_text('String url = "http://evil.example.com/api";',
                          "Test.java", findings)
        self.assertIn("NET-001", [f.rule.id for f in findings])

    def test_net_001_xml_namespace(self):
        findings = []
        self.sc.scan_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/'
            'android">', "AndroidManifest.xml", findings)
        net_001_findings = [f for f in findings if f.rule.id == "NET-001"]
        self.assertEqual(len(net_001_findings), 0)

    def test_weak_crypto(self):
        findings = []
        self.sc.scan_text(
            'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");',
            "Test.java", findings)
        ids = [f.rule.id for f in findings]
        self.assertIn("CRY-001", ids)
        self.assertIn("CRY-005", ids)

    def test_des_word_boundary(self):
        findings = []
        self.sc.scan_text(
            'String mode = "MODES_NODES_CODES_GUIDES_DESTINATION";',
            "Test.java", findings)
        cry_001_findings = [f for f in findings if f.rule.id == "CRY-001"]
        self.assertEqual(len(cry_001_findings), 0)

    def test_mask(self):
        secret = "sk_live_51AbCdEfGhIjKlMnOpQr"
        expected = secret[:5] + "*" * (len(secret) - 10) + secret[-5:]
        self.assertEqual(mask_secret(secret), expected)


class TestCLI(unittest.TestCase):
    def test_cli_rules(self):
        from masa.cli import main
        res = main(["rules"])
        self.assertEqual(res, 0)


class TestEndToEndApk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masa_test_")
        cls.apk = build_apk(cls.tmp)
        cls.result = analyze_apk(cls.apk, use_decompiler=False)

    def test_findings_present(self):
        ids = {f.rule.id for f in self.result.findings}
        for expected in ("SEC-001", "SEC-002", "SEC-003", "SEC-004",
                         "SEC-006", "SEC-008", "SEC-009",
                         "CRY-001", "CRY-002", "CRY-005", "CRY-006",
                         "CRY-008", "CRY-009", "CRY-010",
                         "STO-001", "STO-002", "STO-003", "STO-004",
                         "LOG-001",
                         "NET-001", "NET-002", "NET-003", "NET-004",
                         "NET-005", "NET-007", "NET-008", "NET-009",
                         "NET-012", "NET-013", "NET-014",
                         "INP-001", "PRI-001", "ATH-002",
                         "CFG-001", "CFG-002", "CFG-004", "CFG-005",
                         "SCP-001", "SCP-002", "SCP-003",
                         "NAT-001", "NAT-002", "NAT-003", "NAT-004",
                         "NAT-007", "NAT-008",
                         "BIN-002", "BIN-003",
                         "PERM-001", "PERM-002", "PERM-003", "PERM-004"):
            self.assertIn(expected, ids,
                          "missing finding %s (have %d findings)" %
                          (expected, len(ids)))

    def test_report_scores(self):
        report = build_report(self.result,
                              {"path": self.apk, "sha256": "deadbeef"})
        self.assertLess(report["overall_compliance"], 40)
        self.assertIn(report["grade"], "DF")
        self.assertGreater(report["risk_score"], 50)
        self.assertEqual(report["target"]["platform"], "android")
        json.dumps(report)   # must be serializable

    def test_console(self):
        report = build_report(self.result, {})
        text = console_summary(report)
        self.assertIn("OWASP compliance", text)


class TestEndToEndIpa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masa_test_")
        cls.ipa = build_ipa(cls.tmp)
        cls.result = analyze_ipa(cls.ipa)

    def test_findings_present(self):
        ids = {f.rule.id for f in self.result.findings}
        for expected in ("SEC-001", "SEC-003", "SEC-006", "NET-001",
                         "NET-005", "NET-009", "NET-011", "NET-016",
                         "STO-006", "PRI-001", "NAT-001",
                         "CFG-004", "SCP-004", "BIN-004",
                         "BIN-002", "BIN-003"):
            self.assertIn(expected, ids,
                          "missing finding %s (have %d findings)" %
                          (expected, len(ids)))

    def test_platform(self):
        self.assertEqual(self.result.platform, "ios")
        self.assertEqual(self.result.summary.get("bundle_id"),
                         "com.vulnbank.demo")


class TestReports(unittest.TestCase):
    def test_file_outputs(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="masa_rep_")
        apk = build_apk(tmp)
        result = analyze_apk(apk, use_decompiler=False)
        report = build_report(result, {"path": apk, "sha256": "x"})
        md = os.path.join(tmp, "r.md")
        js = os.path.join(tmp, "r.json")
        html = os.path.join(tmp, "r.html")
        write_markdown(report, md)
        write_json(report, js)
        write_html(report, html)
        for p in (md, js, html):
            self.assertGreater(os.path.getsize(p), 1000)
        with open(md, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("Executive Summary", content)
        self.assertIn("Hardcoded Stripe Secret Key", content)
        self.assertIn("Methodology & Limitations", content)
        with open(html, encoding="utf-8") as fh:
            html_content = fh.read()
        self.assertIn("OWASP Mobile Top 10 Compliance Scoring", html_content)


if __name__ == "__main__":
    unittest.main()
