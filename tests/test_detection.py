"""Detection tests for the IPC, manifest, signing, hardening and iOS checks.

Every rule gets a vulnerable sample that must fire and a safe sample that
must not, and a clean Android/iOS app must scan without medium+ findings.
"""

import io
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from masa import decompile, native  # noqa: E402
from masa.apk import (analyze_apk, apk_signing_schemes,  # noqa: E402
                      biometric_binding_finding, parse_manifest_bytes,
                      protection_level)
from masa.ipa import analyze_ipa  # noqa: E402
from masa.rules import ALL_RULES  # noqa: E402
from masa.samples import make_elf64, make_macho64  # noqa: E402
from masa.scanner import Scanner  # noqa: E402

SEVERE = ("critical", "high", "medium")


def scan_ids(text, filename="Sample.java"):
    findings = []
    Scanner(ALL_RULES).scan_text(text, filename, findings)
    return {f.rule.id for f in findings}


def manifest(body, extra_root=""):
    return ('<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/'
            'android" package="com.example.app">\n'
            '  <uses-sdk android:minSdkVersion="26" '
            'android:targetSdkVersion="34"/>\n%s\n'
            '  <application android:allowBackup="false">\n%s\n'
            '  </application>\n</manifest>\n' % (extra_root, body))


class TempTreeMixin:
    def make_tree(self, files):
        root = tempfile.mkdtemp(prefix="masa_detect_")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, content in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(path, mode) as fh:
                fh.write(content)
        return root

    def analyze_manifest(self, body, extra_root="", **files):
        tree = {"AndroidManifest.xml": manifest(body, extra_root)}
        tree.update(files)
        return analyze_apk(self.make_tree(tree), use_decompiler=False)


# --------------------------------------------------------------- text rules

class TestCodeRules(unittest.TestCase):
    """(rule id, vulnerable snippet, safe snippet)"""

    CASES = [
        ("IPC-001",
         'Intent next = getIntent().getParcelableExtra("next");\n'
         'startActivity(next);',
         'Intent next = getIntent().getParcelableExtra("next");\n'
         'Intent safe = sanitizer.sanitizeByThrowing(next);\n'
         'startActivity(next);'),
        ("IPC-001",
         'val next = intent.getParcelableExtra("n", Intent::class.java)\n'
         'if (next != null) startActivity(next)',
         'val next = intent.getParcelableExtra("n", Intent::class.java)\n'
         'startActivity(Intent(this, Home::class.java))'),
        ("IPC-002",
         'PendingIntent.getActivity(ctx, 0, new Intent("com.x.OPEN"), '
         'PendingIntent.FLAG_MUTABLE);',
         'PendingIntent.getActivity(ctx, 0, new Intent(ctx, Main.class), '
         'PendingIntent.FLAG_MUTABLE);'),
        ("IPC-002",
         'PendingIntent.getBroadcast(this, 0, Intent(Intent.ACTION_VIEW), '
         'PendingIntent.FLAG_MUTABLE)',
         'PendingIntent.getBroadcast(this, 0, Intent(Intent.ACTION_VIEW), '
         'PendingIntent.FLAG_IMMUTABLE)'),
        ("IPC-003", 'sendStickyBroadcast(intent);',
         'sendBroadcast(intent, "com.x.permission.RECEIVE");'),
        ("IPC-004",
         'enforceCallingOrSelfPermission("com.x.WRITE", "no");',
         'enforceCallingPermission("com.x.WRITE", "no");'),
        ("IPC-005",
         'String caller = intent.getStringExtra("calling_package");',
         'int uid = Binder.getCallingUid();'),
        ("IPC-006",
         'registerReceiver(receiver, new IntentFilter("com.x.SYNC"));',
         'ContextCompat.registerReceiver(this, receiver, filter, '
         'ContextCompat.RECEIVER_NOT_EXPORTED);'),
        ("NET-018", 'web.getSettings().setJavaScriptEnabled(true);',
         'web.getSettings().setJavaScriptEnabled(false);'),
        ("PRI-004",
         'cm.setPrimaryClip(ClipData.newPlainText("otp", otp));',
         'cm.setPrimaryClip(ClipData.newPlainText("label", shareUrl));'),
        ("PRI-004", 'UIPasteboard.general.string = password',
         'UIPasteboard.general.string = shareLink'),
        ("STO-008",
         'kSecAttrAccessible as String: kSecAttrAccessibleAlways',
         'kSecAttrAccessible as String: '
         'kSecAttrAccessibleWhenUnlockedThisDeviceOnly'),
        ("STO-009",
         'try data.write(to: url, options: .noFileProtection)',
         'try data.write(to: url, options: .completeFileProtection)'),
    ]

    def test_vulnerable_snippet_fires_and_safe_snippet_does_not(self):
        for rule_id, bad, good in self.CASES:
            with self.subTest(rule=rule_id, case="vulnerable"):
                self.assertIn(rule_id, scan_ids(bad))
            with self.subTest(rule=rule_id, case="safe"):
                self.assertNotIn(rule_id, scan_ids(good))

    def test_absence_rules_do_not_fire_on_their_own_evidence(self):
        # regression: BIN-002/003 used to match "ProGuard"/"RootBeer"
        ids = scan_ids("minifyEnabled true // ProGuard\n"
                       "RootBeer rb = new RootBeer(ctx); rb.isRooted();")
        self.assertNotIn("BIN-002", ids)
        self.assertNotIn("BIN-003", ids)

    def test_hardcoded_endpoint_ignores_xml_namespace_urls(self):
        # regression: NET-010 fired on xmlns:android in every manifest
        ids = scan_ids(manifest(""), "AndroidManifest.xml")
        self.assertNotIn("NET-010", ids)
        self.assertIn("NET-010",
                      scan_ids('url = "https://api.example.com/v1/users"'))

    def test_cleartext_url_skips_identifiers_and_licenses(self):
        for url in ["http://api.insecure-bank.com/v1/balance",
                    "http://cdn.example.com/app.js"]:
            with self.subTest(url):
                self.assertIn("NET-001", scan_ids('u = "%s";' % url))
        # never fetched; found by bench/run.py on real apps
        for url in ["http://schemas.openxmlformats.org/drawingml/2006/main",
                    "http://www.apache.org/licenses/LICENSE-2.0",
                    "http://www.gnu.org/licenses/gpl-3.0.html",
                    "http://schema.org/Person",
                    "http://purl.org/dc/elements/1.1/",
                    "http://javax.xml.XMLConstants/property/accessExternalDTD",
                    "http://xmlpull.org/v1/doc/features.html#indent-output"]:
            with self.subTest(url):
                self.assertNotIn("NET-001", scan_ids('u = "%s";' % url))
        psl = "ir : http://www.nic.ir/\nir\nac.ir\n"
        self.assertNotIn("NET-001", scan_ids(psl, "assets/public_suffix_list.dat"))
        self.assertIn("NET-001", scan_ids(psl, "assets/other.dat"))

    def test_cleartext_url_skips_docs_comments_and_namespaces(self):
        real = 'tiles = "http://openptmap.org/tiles/";'
        self.assertIn("NET-001", scan_ids(real))
        # found on real apps by bench/run.py
        for text, name in [
                ("<http://github.com/jhy/jsoup/issues/34>", "META-INF/CHANGES"),
                ("see http://example.com/a for details", "notes/README"),
                ('"website": "http://developer.android.com/x"', "assets/aboutlibraries.json"),
                ("# file, You can obtain one at http://mozilla.org/MPL/2.0/.", "M.properties"),
                ("// versioning](http://semver.org) where", "api.proto"),
                (" * href=\"http://www.unicode.org/repos/cldr/x.xml\"", "U.java"),
                ('"http://www.itunes.com/dtds/podcast-1.0.dtd"', "A.java"),
                ('"http://dashif.org/guidelines/trickmode"', "A.java"),
                ('"http://search.yahoo.com/mrss/"', "A.java"),
                ("Check http://g.co/dev/packagevisibility.", "A.java"),
                ('"http://apple.com/ns/ical/"', "A.java"),
                ('"http://apache.org/xml/features/disallow-doctype-decl"', "A.java"),
                ('"http://example.com/"', "A.java"),
                ("http://www.eclipse.org/legal/epl-2.0.", "probe.xml")]:
            with self.subTest(text):
                self.assertNotIn("NET-001", scan_ids(text, name))

    def test_hardcoded_endpoint_needs_an_api_shape(self):
        endpoints = ["https://api-v2.soundcloud.com/search",
                     "https://www.googleapis.com/youtube/v3/videos",
                     "https://bandcamp.com/api/mobile/22/band_details",
                     "https://example.com/graphql",
                     "http://backend.example.com:8080/rest/login"]
        # the noise found on real apps by bench/run.py
        links = ["https://www.apache.org/licenses/LICENSE-2.0",
                 "https://github.com/AntennaPod/AntennaPod/issues/123",
                 "https://www.iana.org/time-zones/repository/tz-link.html",
                 "TZURL:https://www.tzurl.org/zoneinfo-global/America/Lima",
                 "http://schemas.openxmlformats.org/drawingml/2006/main",
                 "http://xmlpull.org/v1/doc/features.html#indent-output",
                 "https://github.com/foo/api-docs",
                 "https://developer.android.com/reference/android/app/Activity"]
        for url in endpoints:
            with self.subTest(url):
                self.assertIn("NET-010", scan_ids('u = "%s";' % url))
        for url in links:
            with self.subTest(url):
                self.assertNotIn("NET-010", scan_ids('u = "%s";' % url))


# --------------------------------------------------------------- manifest

class TestProtectionLevel(unittest.TestCase):
    def test_protection_level_normalizes_strings_ints_and_flags(self):
        cases = {None: "normal", "signature": "signature",
                 "signature|knownSigner": "signature", 0: "normal",
                 "0x00000001": "dangerous", 2: "signature",
                 "0x08000012": "signature", 3: "signatureOrSystem"}
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(protection_level(raw), expected)


class TestComponentChecks(TempTreeMixin, unittest.TestCase):
    def ids_for(self, body, extra_root=""):
        result = self.analyze_manifest(body, extra_root)
        return [(f.rule.id, f.extra.get("component")) for f in result.findings
                if f.rule.id.startswith("CFG-00")]

    def test_launcher_activity_is_not_flagged(self):
        body = ('<activity android:name=".Main" android:exported="true">'
                '<intent-filter>'
                '<action android:name="android.intent.action.MAIN"/>'
                '<category android:name="android.intent.category.LAUNCHER"/>'
                '</intent-filter></activity>')
        self.assertEqual(self.ids_for(body), [])

    def test_launcher_with_deep_link_action_is_flagged(self):
        body = ('<activity android:name=".Main" android:exported="true">'
                '<intent-filter>'
                '<action android:name="android.intent.action.MAIN"/>'
                '<action android:name="android.intent.action.VIEW"/>'
                '<category android:name="android.intent.category.LAUNCHER"/>'
                '</intent-filter></activity>')
        self.assertIn(("CFG-001", ".Main"), self.ids_for(body))

    def test_exported_component_without_intent_filter_is_flagged(self):
        body = '<service android:name=".Sync" android:exported="true"/>'
        self.assertEqual(self.ids_for(body), [("CFG-001", ".Sync")])

    def test_explicit_exported_false_is_never_flagged(self):
        body = ('<receiver android:name=".R" android:exported="false">'
                '<intent-filter><action android:name="com.x.A"/>'
                '</intent-filter></receiver>')
        self.assertEqual(self.ids_for(body), [])

    def test_provider_with_read_and_write_permissions_is_protected(self):
        perms = ('<permission android:name="com.x.R" '
                 'android:protectionLevel="signature"/>'
                 '<permission android:name="com.x.W" '
                 'android:protectionLevel="signature"/>')
        body = ('<provider android:name=".P" android:authorities="com.x.p" '
                'android:exported="true" android:readPermission="com.x.R" '
                'android:writePermission="com.x.W"/>')
        self.assertEqual(self.ids_for(body, perms), [])

    def test_provider_with_only_read_permission_is_partial(self):
        body = ('<provider android:name=".P" android:authorities="com.x.p" '
                'android:exported="true" android:readPermission="com.x.R"/>')
        self.assertEqual(self.ids_for(body), [("CFG-006", ".P")])

    def test_component_guarded_by_normal_permission_is_weak(self):
        perms = ('<permission android:name="com.x.USE" '
                 'android:protectionLevel="normal"/>')
        body = ('<service android:name=".S" android:exported="true" '
                'android:permission="com.x.USE"/>')
        self.assertEqual(self.ids_for(body, perms), [("CFG-007", ".S")])

    def test_component_guarded_by_signature_permission_is_safe(self):
        perms = ('<permission android:name="com.x.USE" '
                 'android:protectionLevel="signature|knownSigner"/>')
        body = ('<service android:name=".S" android:exported="true" '
                'android:permission="com.x.USE"/>')
        self.assertEqual(self.ids_for(body, perms), [])

    def test_signature_or_system_permission_is_deprecated(self):
        perms = ('<permission android:name="com.x.OLD" '
                 'android:protectionLevel="signatureOrSystem"/>')
        result = self.analyze_manifest("", perms)
        self.assertIn("CFG-008", {f.rule.id for f in result.findings})

    def test_root_uri_grant_is_flagged_but_scoped_grant_is_not(self):
        for prefix, expected in (("/", ["CFG-009"]), ("/shared/", [])):
            with self.subTest(prefix=prefix):
                body = ('<provider android:name=".F" android:authorities='
                        '"com.x.files" android:exported="false" '
                        'android:grantUriPermissions="true">'
                        '<grant-uri-permission android:pathPrefix="%s"/>'
                        '</provider>' % prefix)
                self.assertEqual([i for i, _c in self.ids_for(body)],
                                 expected)

    def test_file_provider_without_grant_elements_is_not_flagged(self):
        body = ('<provider android:name="androidx.core.content.FileProvider" '
                'android:authorities="com.x.fp" android:exported="false" '
                'android:grantUriPermissions="true"/>')
        self.assertEqual(self.ids_for(body), [])


class TestNetworkConfig(TempTreeMixin, unittest.TestCase):
    APP = ('<application android:networkSecurityConfig="@xml/nsc" '
           'android:allowBackup="false"/>')

    def run_config(self, xml):
        files = {
            "AndroidManifest.xml": manifest("").replace(
                '<application android:allowBackup="false">\n\n'
                '  </application>', self.APP),
            "res/xml/nsc.xml": xml,
        }
        return analyze_apk(self.make_tree(files), use_decompiler=False)

    def test_user_certificates_in_base_config_are_flagged(self):
        result = self.run_config(
            '<network-security-config><base-config><trust-anchors>'
            '<certificates src="user"/></trust-anchors></base-config>'
            '</network-security-config>')
        self.assertIn("NET-017", {f.rule.id for f in result.findings})

    def test_user_certificates_in_debug_overrides_are_allowed(self):
        result = self.run_config(
            '<network-security-config><debug-overrides><trust-anchors>'
            '<certificates src="user"/></trust-anchors></debug-overrides>'
            '</network-security-config>')
        self.assertNotIn("NET-017", {f.rule.id for f in result.findings})

    def test_pin_set_counts_as_certificate_pinning(self):
        result = self.run_config(
            '<network-security-config><domain-config><domain>api.x.com'
            '</domain><pin-set><pin digest="SHA-256">AAAA</pin></pin-set>'
            '</domain-config></network-security-config>')
        self.assertIn("pinning", {p.key for p in result.positives})


# --------------------------------------------------------------- signing

def _zip_bytes(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return buf.getvalue()


def _with_signing_block(data):
    """Splice a fake APK Signing Block in front of the central directory."""
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    block = b"\x00" * 8 + b"APK Sig Block 42"
    out = bytearray(data[:cd_offset] + block + data[cd_offset:])
    new_eocd = eocd + len(block)
    struct.pack_into("<I", out, new_eocd + 16, cd_offset + len(block))
    return bytes(out)


class TestApkSigning(TempTreeMixin, unittest.TestCase):
    def write_apk(self, data):
        root = self.make_tree({"app.apk": data})
        return os.path.join(root, "app.apk")

    def test_signing_schemes_detects_unsigned_v1_and_v2(self):
        cases = {
            "unsigned": (_zip_bytes(["a.txt"]), {"v1": False, "v2plus": False}),
            "v1": (_zip_bytes(["META-INF/CERT.RSA"]),
                   {"v1": True, "v2plus": False}),
            "v1+v2": (_with_signing_block(_zip_bytes(["META-INF/CERT.RSA"])),
                      {"v1": True, "v2plus": True}),
        }
        for label, (data, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(apk_signing_schemes(self.write_apk(data)),
                                 expected)

    def _scan(self, names, min_sdk, v2=False):
        data = _zip_bytes(names)
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("AndroidManifest.xml", manifest("").replace(
                'minSdkVersion="26"', 'minSdkVersion="%d"' % min_sdk))
        data = buf.getvalue()
        if v2:
            data = _with_signing_block(data)
        result = analyze_apk(self.write_apk(data), use_decompiler=False)
        return {f.rule.id: f.severity for f in result.findings
                if f.rule.id in ("BIN-005", "BIN-006")}

    def test_v1_only_is_high_below_api_24_and_medium_above(self):
        self.assertEqual(self._scan(["META-INF/C.RSA"], 21),
                         {"BIN-005": "high"})
        self.assertEqual(self._scan(["META-INF/C.RSA"], 26),
                         {"BIN-005": "medium"})

    def test_v2_signed_apk_has_no_signing_finding(self):
        self.assertEqual(self._scan(["META-INF/C.RSA"], 21, v2=True), {})

    def test_unsigned_apk_is_reported_as_info(self):
        self.assertEqual(self._scan([], 26), {"BIN-006": "info"})


# --------------------------------------------------------------- native

class TestNativeHardening(unittest.TestCase):
    def rule_ids(self, data):
        _info, findings = native.analyze_binary(data, "bin")
        return {f.rule.id for f in findings}

    def test_elf_without_stack_canary_is_flagged(self):
        self.assertIn("NAT-009", self.rule_ids(make_elf64(b"puts\x00")))
        self.assertNotIn("NAT-009",
                         self.rule_ids(make_elf64(b"__stack_chk_fail\x00")))

    def test_macho_cryptid_is_read_at_offset_16(self):
        # regression: the 64-bit command was read at +20 (padding)
        self.assertIn("BIN-004", self.rule_ids(make_macho64(b"x" * 8)))
        self.assertNotIn("BIN-004", self.rule_ids(_encrypted_macho(b"x" * 8)))

    def test_xml_plist_doctype_is_not_cleartext_traffic(self):
        ids = scan_ids(plistlib.dumps({"a": 1}).decode(), "Info.plist")
        self.assertNotIn("NET-001", ids)

    def test_macho_objc_without_arc_is_flagged(self):
        mrc = make_macho64(b"_objc_msgSend\x00___stack_chk_fail\x00")
        arc = make_macho64(b"_objc_msgSend\x00_objc_release\x00"
                           b"___stack_chk_fail\x00")
        swift_only = make_macho64(b"_swift_release\x00___stack_chk_fail\x00")
        self.assertIn("NAT-010", self.rule_ids(mrc))
        self.assertNotIn("NAT-010", self.rule_ids(arc))
        self.assertNotIn("NAT-010", self.rule_ids(swift_only))
        self.assertNotIn("NAT-009", self.rule_ids(arc))


# --------------------------------------------------------------- biometrics

class TestBiometricBinding(unittest.TestCase):
    def test_biometric_gate_without_key_binding_is_flagged(self):
        cases = [
            ("prompt = BiometricPrompt(this, ex, cb)\n"
             "prompt.authenticate(info)", True),
            ("prompt = BiometricPrompt(this, ex, cb)\nprompt.authenticate("
             "info, BiometricPrompt.CryptoObject(cipher))", False),
            ("let ctx = LAContext()\nctx.evaluatePolicy(.x, localizedReason:"
             " r) { ok, _ in }", True),
            ("let ctx = LAContext()\nctx.evaluatePolicy(.x, localizedReason:"
             " r) { _, _ in }\nSecAccessControlCreateWithFlags(nil, a, "
             ".biometryCurrentSet, nil)", False),
            ("no biometrics here", False),
        ]
        for pool, flagged in cases:
            with self.subTest(pool=pool.splitlines()[0]):
                self.assertEqual(biometric_binding_finding(pool) is not None,
                                 flagged)


# --------------------------------------------------------------- decompiler

class TestDecompilePipeline(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="masa_dec_")
        self.addCleanup(shutil.rmtree, self.out, True)

    def fake_run(self, produce_java_for):
        calls = []

        def run(cmd, timeout=600):
            calls.append(cmd)
            if any(tool in cmd[0] for tool in produce_java_for):
                with open(os.path.join(self.out, "A.java"), "w") as fh:
                    fh.write("class A {}")
                return True
            return False
        return run, calls

    def test_jadx_is_preferred_over_apktool(self):
        run, calls = self.fake_run(["jadx", "apktool"])
        tools = {"jadx": "/bin/jadx", "apktool": "/bin/apktool"}
        with mock.patch.object(decompile, "_run", run):
            used = decompile.decompile_apk("app.apk", self.out, tools)
        self.assertEqual(used, "jadx")
        self.assertEqual(len(calls), 1)

    def test_dex2jar_then_cfr_runs_when_jadx_is_missing(self):
        run, calls = self.fake_run(["d2j-dex2jar", "java"])
        tools = {"d2j-dex2jar": "/bin/d2j-dex2jar", "java": "/bin/java",
                 "cfr.jar": "/opt/cfr.jar"}
        with mock.patch.object(decompile, "_run", run):
            used = decompile.decompile_apk("app.apk", self.out, tools)
        self.assertEqual(used, "dex2jar+cfr")
        self.assertEqual(calls[0][:2], ["/bin/d2j-dex2jar", "-f"])
        self.assertEqual(calls[1][:3], ["/bin/java", "-jar", "/opt/cfr.jar"])
        self.assertIn("--outputdir", calls[1])

    def test_dex2jar_without_cfr_is_skipped(self):
        run, calls = self.fake_run([])
        with mock.patch.object(decompile, "_run", run):
            used = decompile.decompile_apk(
                "app.apk", self.out, {"d2j-dex2jar": "/bin/d2j-dex2jar"})
        self.assertIsNone(used)
        self.assertEqual(calls, [])

    def test_tool_that_exits_zero_but_writes_nothing_is_not_success(self):
        with mock.patch.object(decompile, "_run", return_value=True):
            used = decompile.decompile_apk("app.apk", self.out,
                                           {"apktool": "/bin/apktool"})
        self.assertIsNone(used)

    def test_cfr_jar_is_picked_up_from_environment(self):
        jar = os.path.join(self.out, "cfr.jar")
        open(jar, "w").close()
        with mock.patch.dict(os.environ, {decompile.CFR_JAR_ENV: jar}), \
                mock.patch.object(decompile, "which", return_value=None):
            self.assertEqual(decompile.available_tools(), {"cfr.jar": jar})


# --------------------------------------------------------------- clean apps

CLEAN_JAVA = '''package com.example.app;
public class Main extends android.app.Activity {
    protected void onCreate(android.os.Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        Intent next = getIntent().getParcelableExtra("next");
        Intent safe = new IntentSanitizer.Builder().build().sanitizeByThrowing(next);
        PendingIntent.getActivity(this, 0, new Intent(this, Main.class), PendingIntent.FLAG_IMMUTABLE);
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom rnd = new SecureRandom();
        prompt.authenticate(info, new BiometricPrompt.CryptoObject(c));
        if (new RootBeer(this).isRooted()) finish();
    }
}
'''

CLEAN_MANIFEST = manifest(
    '<activity android:name=".Main" android:exported="true">'
    '<intent-filter><action android:name="android.intent.action.MAIN"/>'
    '<category android:name="android.intent.category.LAUNCHER"/>'
    '</intent-filter></activity>\n'
    '<service android:name=".Sync" android:exported="true" '
    'android:permission="com.example.app.SYNC"/>\n'
    '<provider android:name="androidx.core.content.FileProvider" '
    'android:authorities="com.example.app.files" android:exported="false" '
    'android:grantUriPermissions="true"/>',
    '<permission android:name="com.example.app.SYNC" '
    'android:protectionLevel="signature"/>'
).replace('android:allowBackup="false"',
          'android:allowBackup="false" '
          'android:networkSecurityConfig="@xml/network_security_config"')

CLEAN_NSC = '''<network-security-config>
  <base-config cleartextTrafficPermitted="false"/>
  <domain-config><domain>api.example.com</domain>
    <pin-set><pin digest="SHA-256">AAAA</pin></pin-set></domain-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
'''


def _encrypted_macho(payload):
    data = bytearray(make_macho64(payload))
    struct.pack_into("<I", data, 32 + 0x48 + 16, 1)   # cryptid = 1
    return bytes(data)


class TestAppContext(TempTreeMixin, unittest.TestCase):
    """Checks that need more than one file: found on real apps by bench."""

    def analyze(self, files):
        return {f.rule.id for f in analyze_apk(self.make_tree(files),
                                                use_decompiler=False).findings}

    def test_telephony_ids_need_read_phone_state(self):
        java = "class A { String id(TelephonyManager tm) { return tm.getDeviceId(); } }"
        perm = '<uses-permission android:name="android.permission.READ_PHONE_STATE"/>'
        self.assertNotIn("PRI-001", self.analyze(
            {"AndroidManifest.xml": manifest(""), "src/A.java": java}))
        self.assertIn("PRI-001", self.analyze(
            {"AndroidManifest.xml": manifest("", perm), "src/A.java": java}))

    def test_short_class_names_count_as_obfuscation(self):
        from masa.samples import make_dex
        plain = make_dex(["Lcom/example/app/MainActivity;", "Lcom/example/app/Util;"])
        r8 = make_dex(["Lsg/vantagepoint/a/a;", "Lsg/vantagepoint/a/b;",
                       "Lsg/vantagepoint/a/c;", "Lsg/vantagepoint/uncrackable1/MainActivity;"])
        self.assertIn("BIN-002", self.analyze(
            {"AndroidManifest.xml": manifest(""), "classes.dex": plain}))
        self.assertNotIn("BIN-002", self.analyze(
            {"AndroidManifest.xml": manifest(""), "classes.dex": r8}))


class TestCleanApps(TempTreeMixin, unittest.TestCase):
    """A well-built app must not drown in findings (false-positive guard)."""

    def assertNoSevere(self, result):
        severe = [(f.rule.id, f.file, f.severity) for f in result.findings
                  if f.severity in SEVERE]
        self.assertEqual(severe, [])

    def test_clean_android_project_has_no_medium_or_higher_findings(self):
        root = self.make_tree({
            "app/src/main/AndroidManifest.xml": CLEAN_MANIFEST,
            "app/src/main/res/xml/network_security_config.xml": CLEAN_NSC,
            "app/src/main/java/com/example/app/Main.java": CLEAN_JAVA,
            "app/build.gradle": "android { buildTypes { release { "
                                "minifyEnabled true } } }\n",
        })
        result = analyze_apk(root, use_decompiler=False)
        self.assertNoSevere(result)
        ids = {f.rule.id for f in result.findings}
        for absent in ("BIN-002", "BIN-003", "PRI-005", "ATH-003", "NET-010"):
            with self.subTest(rule=absent):
                self.assertNotIn(absent, ids)

    def test_clean_ios_bundle_has_no_medium_or_higher_findings(self):
        info = {"CFBundleIdentifier": "com.example.app",
                "CFBundleExecutable": "App", "MinimumOSVersion": "16.0"}
        binary = _encrypted_macho(
            b"_objc_msgSend\x00_objc_release\x00___stack_chk_fail\x00"
            b"SecItemAdd\x00kSecAttrAccessibleWhenUnlockedThisDeviceOnly\x00"
            b"LAContext\x00evaluatePolicy\x00"
            b"SecAccessControlCreateWithFlags\x00isJailbroken\x00")
        root = self.make_tree({
            "Payload/App.app/Info.plist": plistlib.dumps(info),
            "Payload/App.app/App": binary,
        })
        result = analyze_ipa(root)
        self.assertNoSevere(result)
        self.assertIs(result.binaries[0]["info"]["encrypted"], True)
        self.assertNotIn("ATH-003", {f.rule.id for f in result.findings})


class TestManifestModel(unittest.TestCase):
    def test_xml_manifest_exposes_permissions_and_uri_grants(self):
        info = parse_manifest_bytes(manifest(
            '<provider android:name=".P" android:authorities="a" '
            'android:readPermission="com.x.R" android:grantUriPermissions='
            '"true"><grant-uri-permission android:path="/"/></provider>',
            '<permission android:name="com.x.R" '
            'android:protectionLevel="dangerous"/>').encode())
        self.assertEqual(info.custom_permissions, {"com.x.R": "dangerous"})
        prov = info.components[0]
        self.assertEqual(prov["read_permission"], "com.x.R")
        self.assertTrue(prov["grant_uri_permissions"])
        self.assertEqual(prov["uri_grants"], [{"path": "/"}])


if __name__ == "__main__":
    unittest.main()
