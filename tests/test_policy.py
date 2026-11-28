"""Tests for v1.3: file scoping, CWE/MASVS ids, suppressions and baselines."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from masa import policy  # noqa: E402
from masa.cli import main  # noqa: E402
from masa.models import Finding  # noqa: E402
from masa.report import build_sarif  # noqa: E402
from masa.rules import ALL_RULES, BY_ID  # noqa: E402
from masa.scanner import Scanner, file_kind, inline_suppression  # noqa: E402
from masa.taxonomy import TAXA  # noqa: E402

MANIFEST = ('<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/'
            'android" package="com.example.app">\n'
            '  <uses-sdk android:minSdkVersion="26" '
            'android:targetSdkVersion="34"/>\n'
            '  <application android:allowBackup="false"/>\n</manifest>\n')

AWS = 'String aws = "AKIAIOSFODNN7EXAMPLE";'


def scan(text, filename):
    findings = []
    Scanner(ALL_RULES).scan_text(text, filename, findings)
    return findings


def ids(findings):
    return {f.rule.id for f in findings}


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestTaxonomy(unittest.TestCase):
    def test_every_rule_is_mapped(self):
        self.assertEqual(set(TAXA), {r.id for r in ALL_RULES})

    def test_ids_are_well_formed(self):
        for rule in ALL_RULES:
            with self.subTest(rule.id):
                if rule.cwe:
                    self.assertRegex(rule.cwe, r"^CWE-\d+$")
                if rule.masvs:
                    self.assertRegex(rule.masvs, r"^MASVS-[A-Z]+-\d$")

    def test_programmatic_findings_carry_their_ids(self):
        # manifest/binary/behaviour findings used to drop CWE and MASVS
        import tempfile as _t
        from masa.apk import analyze_apk
        from masa.samples import build_apk
        d = _t.mkdtemp(prefix="masa_taxa_")
        self.addCleanup(shutil.rmtree, d, True)
        for f in analyze_apk(build_apk(d), use_decompiler=False).findings:
            cwe, masvs = TAXA[f.rule.id]
            with self.subTest(f.rule.id):
                self.assertEqual((f.to_dict()["cwe"], f.to_dict()["masvs"]), (cwe, masvs))

    def test_sarif_rule_tags(self):
        f = Finding(BY_ID["SEC-001"], file="a.java", line=1, snippet=AWS)
        data = {"findings": [f.to_dict()],
                "rules_reference": [BY_ID["SEC-001"].to_dict()]}
        rule = build_sarif(data)["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertIn("external/cwe/cwe-798", rule["properties"]["tags"])
        self.assertIn("MASVS-STORAGE-1", rule["properties"]["tags"])


class TestFileScoping(unittest.TestCase):
    def test_file_kind(self):
        cases = {"a/B.java": "source", "x.smali": "source",
                 "lib.c": "native_source", "res/values/strings.xml": "config",
                 "AndroidManifest.xml (normalized)": "config",
                 "README.md": "doc", "LICENSE": "doc", "x/y.bin": "other",
                 "META-INF/CERT.SF": "config", "META-INF/MANIFEST.MF": "config"}
        for name, kind in cases.items():
            with self.subTest(name):
                self.assertEqual(file_kind(name), kind)

    def test_native_rule_skips_java(self):
        found = ids(scan('MessageDigest md = MessageDigest.getInstance("MD5");',
                         "A.java"))
        self.assertIn("CRY-002", found)
        self.assertNotIn("NAT-002", found)

    def test_weak_native_crypto_is_an_import_not_a_string(self):
        from masa import native
        from masa.samples import make_elf64

        def nat002(blob):
            return [f.snippet for f in native.analyze_binary(blob, "lib/x/libapp.so")[1]
                    if f.rule.id == "NAT-002"]
        weak = ("MD5_Init", "DES_key_schedule", "RC4_set_key", "EVP_sha1")
        # a library that calls libcrypto's weak primitives
        self.assertEqual(sorted(nat002(make_elf64(b"", imports=weak + ("puts",)))),
                         sorted(weak))
        # a library that implements them (BoringSSL inside libflutter.so,
        # libcronet, WebRTC): exports and name tables are not use
        impl = make_elf64(b"DES-EDE3-CBC\x00ecdsa-with-SHA1\x00sha1_compile\x00",
                          imports=("malloc",), exports=weak)
        self.assertEqual(nat002(impl), [])

    def test_crypto_libraries_skip_weak_crypto_string_rules(self):
        def native_ids(strings, name):
            findings = []
            Scanner(ALL_RULES).scan_strings(strings, name, findings)
            return ids(findings)
        weak = ["RC4", "AES/ECB/NoPadding"]
        self.assertTrue({"CRY-004", "CRY-005"} <= native_ids(weak, "lib/arm64-v8a/libapp.so"))
        for lib in ("libconscrypt_jni.so", "libcrypto.so", "libssl.so.3"):
            with self.subTest(lib):
                found = native_ids(weak + ["AKIAIOSFODNN7EXAMPLE"],
                                   "lib/arm64-v8a/" + lib)
                self.assertFalse({"CRY-004", "CRY-005"} & found)
                self.assertIn("SEC-001", found)   # other rules still run

    def test_des_rule_wants_a_transformation_not_a_catalog(self):
        def dex_ids(s):
            findings = []
            Scanner(ALL_RULES).scan_strings([s], "classes.dex", findings)
            return ids(findings)
        for s in ("DES", "DESede", "DES/CBC/PKCS5Padding", "DESede/ECB/NoPadding"):
            with self.subTest(s):
                self.assertIn("CRY-001", dex_ids(s))
        self.assertIn("CRY-001", ids(scan(
            'KeyGenerator.getInstance("DESede");', "K.java")))
        self.assertIn("CRY-001", ids(scan(
            "CCCrypt(kCCEncrypt, kCCAlgorithmDES, 0, k, 8, NULL, d, n, o, m, &l);",
            "C.m")))
        # library catalogs found on real apps by bench/run.py
        for s in ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "fts3DestroyMethod",
                  "des-ede3-cbc", "DES-EDE3-CBC",
                  "Lorg/bouncycastle/jcajce/provider/symmetric/DESede",
                  "IESCipher$ECIESwithDESedeCBC", "DESede engine not initialised",
                  "CCCrypt"):
            with self.subTest(s):
                self.assertNotIn("CRY-001", dex_ids(s))

    def test_tracking_sdks_by_name_not_by_english_word(self):
        def dex_ids(s):
            findings = []
            Scanner(ALL_RULES).scan_strings([s], "classes.dex", findings)
            return ids(findings)
        for s in ("Lcom/adjust/sdk/Adjust;", "com.adjust.sdk.AdjustConfig",
                  "ADJConfig", "Lcom/google/firebase/analytics/FirebaseAnalytics;",
                  "Lcom/google/android/gms/analytics/GoogleAnalytics;",
                  "Lcom/appsflyer/AppsFlyerLib;", "com.mixpanel.android.mpmetrics.MixpanelAPI"):
            with self.subTest(s):
                self.assertIn("PRI-002", dex_ids(s))
        # found on real apps by bench/run.py
        for s in ("adjustListItemSelectionBounds", "setAdjustViewBounds",
                  "Landroid/widget/AbsListView$SelectionBoundsAdjuster;",
                  "whereRangeAdjust", "ADJUST",
                  "Lcom/google/android/gms/analytics/AnalyticsService;"):
            with self.subTest(s):
                self.assertNotIn("PRI-002", dex_ids(s))

    def test_staging_endpoint_needs_a_staging_host_label(self):
        for url in ("https://api.vulnbank.staging.internal/v1/ping",
                    "https://staging.tasks.org/", "http://api-dev.example.com/x",
                    "https://qa2.example.com", "http://uat.bank.example/login",
                    "http://backend.test/", "https://printer.local/"):
            with self.subTest(url):
                self.assertIn("CFG-005", ids(scan('u = "%s";' % url, "A.java")))
        # found on real apps by bench/run.py
        for url in ("https://developer.android.com/jetpack/androidx",
                    "https://developers.google.com/protocol-buffers/",
                    "https://developer.mozilla.org/en-US/docs/Web",
                    "https://protobuf.dev/", "https://libretube.dev",
                    "https://amp.dev/", "https://google.aip.dev/122"):
            with self.subTest(url):
                self.assertNotIn("CFG-005", ids(scan('u = "%s";' % url, "A.java")))

    def test_low_precision_rules_found_by_bench(self):
        def dex_ids(s):
            findings = []
            Scanner(ALL_RULES).scan_strings([s], "classes.dex", findings)
            return ids(findings)
        cases = [  # (rule, should fire, text, file)
            ("NET-008", True, 'u = "http://192.168.1.20:8080/api";', "A.java"),
            ("NET-008", False, 'u = "http://127.0.0.1:8080/";', "A.java"),
            ("NET-006", True, "sslPinning = false;", "A.java"),
            ("NET-006", False, '"allowInsecure": "Allow insecure HTTP requests",', "en.json"),
            ("NET-006", False, "builder.forceAllowInsecureDecoderComponents(true);", "A.java"),
            ("IPC-004", True, 'checkCallingOrSelfPermission("x.ADMIN");', "A.java"),
            ("INP-002", True, "File f = new File(dir, name);", "A.java"),
            ("CRY-004", True, 'Cipher.getInstance("ARCFOUR");', "A.java"),
            ("CRY-004", False, ".*(_DES|DH_|RC4|NULL).*", "A.java"),
            ("CFG-005", True, 'u = "https://staging.tasks.org/";', "A.java"),
            ("CFG-005", False, '"https://dev-pages.brave.software/navigation-tracking/*",',
             "debounce.json")]
        for rule, fires, text, name in cases:
            with self.subTest(rule=rule, text=text):
                (self.assertIn if fires else self.assertNotIn)(rule, ids(scan(text, name)))
        # in dex, a bare method name or a message is not a call
        for rule, s in (("IPC-004", "checkCallingOrSelfPermission"),
                        ("INP-002", "Did you call Uri.parse()? Use new File(path)"),
                        ("CRY-004", "Alg.Alias.Cipher.RC4")):
            with self.subTest(rule=rule, s=s):
                self.assertNotIn(rule, dex_ids(s))
        self.assertIn("CRY-004", dex_ids("RC4"))

    def test_private_key_needs_a_body(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2
        key = "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----" % body
        enc = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
               "DEK-Info: AES-128-CBC,3F17F5316E2BAC89\n\n%s\n" % body)
        self.assertIn("SEC-007", ids(scan(key, "res/raw/key.pem")))
        self.assertIn("SEC-007", ids(scan(enc, "res/raw/key.pem")))
        # PEM parser constants (sshj, BouncyCastle): header only
        for s in ("-----BEGIN OPENSSH PRIVATE KEY-----",
                  "File header not found [-----BEGIN OPENSSH PRIVATE KEY-----]"):
            with self.subTest(s):
                findings = []
                Scanner(ALL_RULES).scan_strings([s], "classes.dex", findings)
                self.assertNotIn("SEC-007", ids(findings))

    def test_credits_and_license_texts_by_content(self):
        url = 'u = "http://www.slf4j.org/x"'
        credits = '{"libraries": [{"uniqueId": "org.slf4j:slf4j-api", "artifactVersion": "2.0", "website": "http://www.slf4j.org"}]}'
        gpl = "    GNU GENERAL PUBLIC LICENSE\n  Version 2\n see http://www.gnu.org/philosophy/x.html"
        self.assertIn("NET-001", ids(scan(url, "res/M7.json")))
        self.assertNotIn("NET-001", ids(scan(credits, "res/M7.json")))
        self.assertNotIn("NET-001", ids(scan(gpl, "res/XB")))
        self.assertIn("SEC-001", ids(scan(gpl + "\n" + AWS, "res/XB")))  # secrets still found
        self.assertNotIn("NET-001", ids(scan('"http://jabber.org/protocol/disco#info"', "A.java")))

    def test_code_rules_skip_docs(self):
        text = 'Cipher.getInstance("DES/ECB/PKCS5Padding")'
        self.assertIn("CRY-001", ids(scan(text, "Crypto.java")))
        self.assertNotIn("CRY-001", ids(scan(text, "NOTES.md")))

    def test_secrets_are_found_everywhere(self):
        for name in ("A.java", "README.md", "strings.xml", "blob"):
            with self.subTest(name):
                self.assertIn("SEC-001", ids(scan(AWS, name)))


class TestInlineSuppression(unittest.TestCase):
    def sup(self, text, rule="SEC-001"):
        return [f.suppression for f in scan(text, "A.java")
                if f.rule.id == rule]

    def test_same_line_with_reason(self):
        s = self.sup(AWS + "  // masa-ignore: SEC-001 -- AWS docs example")
        self.assertEqual(s, [{"kind": "inSource",
                              "justification": "AWS docs example"}])

    def test_bare_ignore_covers_every_rule(self):
        s = self.sup(AWS + "  // masa-ignore")
        self.assertEqual(s[0]["justification"], "suppressed inline")

    def test_comment_line_above(self):
        s = self.sup("// masa-ignore: SEC-001, CRY-001 -- fixture\n" + AWS)
        self.assertEqual(s[0]["justification"], "fixture")

    def test_other_rule_id_does_not_suppress(self):
        self.assertEqual(self.sup(AWS + " // masa-ignore: CRY-001"), [None])

    def test_trailing_ignore_does_not_leak_to_next_line(self):
        text = 'int x = 1; // masa-ignore: SEC-001\n' + AWS
        self.assertEqual(self.sup(text), [None])

    def test_xml_and_block_comments(self):
        lines = ['<!-- masa-ignore: SEC-001 -- sample -->', AWS]
        self.assertEqual(inline_suppression(lines, 2, "SEC-001"), "sample")
        lines = [AWS + " /* masa-ignore: SEC-001 -- why */"]
        self.assertEqual(inline_suppression(lines, 1, "SEC-001"), "why")


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masa_cfg_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def test_json_config(self):
        path = self.write(".masa.json", json.dumps({"ignore": [
            {"rule": "SEC-001", "path": "res/*.xml", "reason": "demo"}]}))
        self.assertEqual(policy.find_config(self.tmp), path)
        self.assertEqual(len(policy.load_config(path)["ignore"]), 1)

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib needs 3.11+")
    def test_toml_config(self):
        path = self.write(".masa.toml", '[[ignore]]\npath = "assets/*"\n'
                                        'reason = "vendored"\n')
        self.assertEqual(policy.load_config(path)["ignore"][0]["path"],
                         "assets/*")

    def test_bad_entries_are_rejected(self):
        bad = [{"rule": "SEC-001"},                      # no reason
               {"reason": "x"},                          # no rule or path
               {"rule": "SEC-001", "reason": "x", "paths": "a"}]  # typo
        for entry in bad:
            with self.subTest(entry):
                path = self.write("c.json", json.dumps({"ignore": [entry]}))
                with self.assertRaises(ValueError):
                    policy.load_config(path)

    def test_apply_ignores(self):
        rule = BY_ID["SEC-001"]
        fs = [Finding(rule, file="res/values/strings.xml"),
              Finding(rule, file="assets/sdk/a.js"),
              Finding(rule, file="src/Main.java"),
              Finding(BY_ID["CRY-001"], file="res/values/strings.xml")]
        n = policy.apply_ignores(fs, [
            {"rule": "SEC-001", "path": "res/*", "reason": "a"},
            {"path": "assets/*", "reason": "b"}])
        self.assertEqual(n, 2)
        self.assertEqual([bool(f.suppression) for f in fs],
                         [True, True, False, False])


class TestFingerprint(unittest.TestCase):
    def test_line_shift_keeps_fingerprint(self):
        a = scan(AWS, "A.java")[0].to_dict()
        b = scan("\n\n// new header\n  " + AWS, "A.java")[0].to_dict()
        self.assertNotEqual(a["line"], b["line"])
        self.assertEqual(a["fingerprint"], b["fingerprint"])

    def test_different_file_changes_fingerprint(self):
        a = scan(AWS, "A.java")[0].to_dict()
        b = scan(AWS, "B.java")[0].to_dict()
        self.assertNotEqual(a["fingerprint"], b["fingerprint"])


class TestCliPolicy(unittest.TestCase):
    """End to end: scan a project, take a baseline, add a finding."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masa_policy_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = os.path.join(self.tmp, "app")
        self.write("AndroidManifest.xml", MANIFEST)
        self.write("src/Main.java", "class Main {\n  " + AWS + "\n}\n")
        self.out = os.path.join(self.tmp, "out")
        # run from an empty dir so no stray config is picked up
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.cwd)

    def write(self, rel, content):
        path = os.path.join(self.app, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    def analyze(self, *extra):
        code, out, err = run(["analyze", self.app, "-o", self.out,
                              "--sarif", os.path.join(self.out, "r.sarif"),
                              "--fail-on", "high"] + list(extra))
        with open(os.path.join(self.out, "app.report.json")) as fh:
            report = json.load(fh)
        with open(os.path.join(self.out, "r.sarif")) as fh:
            sarif = json.load(fh)
        return code, out, err, report, sarif

    def test_baseline_only_new_findings_fail(self):
        code, _o, _e, first, _s = self.analyze()
        self.assertEqual(code, 1)
        base = os.path.join(self.tmp, "baseline.json")
        shutil.copy(os.path.join(self.out, "app.report.json"), base)

        # unchanged app, code moved down: everything is known, gate passes
        self.write("src/Main.java", "// header\n\nclass Main {\n  " + AWS +
                   "\n}\n")
        code, out, _e, report, sarif = self.analyze("--baseline", base)
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(len(report["baselined"]), len(first["findings"]))
        self.assertIn("Baseline: 0 new", out)
        states = {r["baselineState"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(states, {"unchanged"})

        # a new secret appears: only it is new, and the gate fails again
        self.write("src/Keys.java", 'String gh = '
                   '"ghp_abcdefghijklmnopqrstuvwxyz0123456789";\n')
        code, _o, _e, report, _s = self.analyze("--baseline", base)
        self.assertEqual(code, 1)
        self.assertEqual({f["id"] for f in report["findings"]}, {"SEC-004"})

    def test_config_suppression_passes_gate(self):
        cfg = os.path.join(self.tmp, ".masa.json")
        with open(cfg, "w") as fh:
            json.dump({"ignore": [{"path": "src/*", "reason": "test keys"}]},
                      fh)
        code, out, _e, report, sarif = self.analyze()
        self.assertEqual(code, 0, out)
        self.assertTrue(report["suppressed"])
        self.assertTrue(all(f["file"] != "src/Main.java"
                            for f in report["findings"]))
        self.assertIn("Suppressed:", out)
        sup = [r for r in sarif["runs"][0]["results"] if "suppressions" in r]
        self.assertEqual(sup[0]["suppressions"][0],
                         {"kind": "external", "justification": "test keys"})

    def test_inline_suppression_passes_gate(self):
        self.write("src/Main.java", "class Main {\n  " + AWS +
                   " // masa-ignore: SEC-001 -- AWS docs key\n}\n")
        code, _o, _e, report, _s = self.analyze()
        self.assertEqual(code, 0)
        self.assertEqual(report["suppressed"][0]["suppression"]["kind"],
                         "inSource")

    def test_bad_config_is_an_error(self):
        with open(os.path.join(self.tmp, ".masa.json"), "w") as fh:
            fh.write('{"ignore": [{"rule": "SEC-001"}]}')
        code, _o, err = run(["analyze", self.app])
        self.assertEqual(code, 2)
        self.assertIn("reason", err)

    def test_bad_baseline_is_an_error(self):
        path = os.path.join(self.tmp, "nope.json")
        with open(path, "w") as fh:
            fh.write("[]")
        code, _o, err = run(["analyze", self.app, "--baseline", path])
        self.assertEqual(code, 2)
        # a pre-1.3 report has no fingerprints
        with open(path, "w") as fh:
            json.dump({"findings": [{"id": "SEC-001"}]}, fh)
        code, _o, err = run(["analyze", self.app, "--baseline", path])
        self.assertEqual(code, 2)
        self.assertIn("regenerate", err)


if __name__ == "__main__":
    unittest.main()
