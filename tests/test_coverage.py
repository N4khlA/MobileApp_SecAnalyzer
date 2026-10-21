"""Coverage tracking: a file that is not analysed must never disappear silently."""

import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from masa import apk as apk_mod  # noqa: E402
from masa import archive, coverage  # noqa: E402
from masa import ipa as ipa_mod  # noqa: E402
from masa.apk import analyze_apk  # noqa: E402
from masa.cli import EXIT_ERROR, EXIT_GATE, EXIT_OK, gate, main  # noqa: E402
from masa.ipa import analyze_ipa  # noqa: E402
from masa.report import build_report, build_sarif, console_summary  # noqa: E402
from masa.report import _html, _md  # noqa: E402
from masa.samples import build_apk, build_ipa  # noqa: E402

# Offsets of fields in the zip local file header and central directory entry.
LOCAL_FLAGS, LOCAL_METHOD, LOCAL_SIZE = 6, 8, 22
CENTRAL_FLAGS, CENTRAL_METHOD, CENTRAL_SIZE = 8, 10, 24


def _entry_offsets(raw, name):
    """Return (central_dir_offset, local_header_offset) for an entry."""
    pos = 0
    while True:
        cd = raw.find(b"PK\x01\x02", pos)
        if cd < 0:
            raise KeyError(name)
        nlen = struct.unpack("<H", raw[cd + 28:cd + 30])[0]
        if raw[cd + 46:cd + 46 + nlen] == name.encode():
            return cd, struct.unpack("<I", raw[cd + 42:cd + 46])[0]
        pos = cd + 4


def _patch(path, name, central_field, local_field, fmt, value):
    raw = bytearray(open(path, "rb").read())
    cd, lo = _entry_offsets(raw, name)
    size = struct.calcsize(fmt)
    raw[cd + central_field:cd + central_field + size] = struct.pack(fmt, value)
    raw[lo + local_field:lo + local_field + size] = struct.pack(fmt, value)
    open(path, "wb").write(raw)


def _corrupt_data(path, name):
    """Overwrite the start of an entry's deflate stream with an invalid block."""
    raw = bytearray(open(path, "rb").read())
    _cd, lo = _entry_offsets(raw, name)
    nlen, xlen = struct.unpack("<HH", raw[lo + 26:lo + 30])
    start = lo + 30 + nlen + xlen
    raw[start:start + 4] = b"\xff\xff\xff\xff"
    open(path, "wb").write(raw)


def _quiet(fn, *args, **kwargs):
    with redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def _skipped(result):
    return {i["file"]: i for i in result.coverage.to_dict()["skipped"]}


def _from_file(result, name):
    return [f for f in result.findings if f.file == name]


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masa_cov_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.apk = build_apk(self.tmp)

    def copy(self, name):
        dst = os.path.join(self.tmp, name)
        shutil.copy(self.apk, dst)
        return dst


class TestCleanScan(_Fixture):
    def test_intact_apk_is_complete(self):
        result = _quiet(analyze_apk, self.apk, use_decompiler=False)
        cov = result.coverage.to_dict()
        self.assertTrue(cov["complete"])
        self.assertEqual(cov["skipped"], [])
        self.assertEqual(cov["files_seen"], 7)

    def test_intact_ipa_is_complete(self):
        ipa = build_ipa(self.tmp)
        result = _quiet(analyze_ipa, ipa)
        self.assertTrue(result.coverage.complete)


class TestDamagedEntries(_Fixture):
    def test_forged_size_is_recorded_not_dropped(self):
        baseline = _quiet(analyze_apk, self.apk, use_decompiler=False)
        path = self.copy("forged.apk")
        _patch(path, "classes.dex", CENTRAL_SIZE, LOCAL_SIZE, "<I", 1)
        result = _quiet(analyze_apk, path, use_decompiler=False)

        self.assertTrue(_from_file(baseline, "classes.dex"))
        self.assertFalse(_from_file(result, "classes.dex"))
        self.assertFalse(result.coverage.complete)
        item = _skipped(result)["classes.dex"]
        self.assertEqual(item["reason"], coverage.UNREADABLE)
        self.assertIn("BadZipFile", item["detail"])

    def test_corrupt_deflate_stream_does_not_abort_scan(self):
        path = self.copy("corrupt.apk")
        _corrupt_data(path, "classes.dex")
        result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertIn("error", _skipped(result)["classes.dex"]["detail"])
        self.assertTrue(result.findings)

    def test_encrypted_entry(self):
        path = self.copy("encrypted.apk")
        _patch(path, "assets/config.json", CENTRAL_FLAGS, LOCAL_FLAGS, "<H", 1)
        result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertIn("RuntimeError",
                      _skipped(result)["assets/config.json"]["detail"])

    def test_unsupported_compression(self):
        path = self.copy("method99.apk")
        _patch(path, "res/values/strings.xml", CENTRAL_METHOD, LOCAL_METHOD,
               "<H", 99)
        result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertIn("NotImplementedError",
                      _skipped(result)["res/values/strings.xml"]["detail"])

    def test_oversized_archive_is_still_an_error(self):
        with mock.patch.object(archive, "MAX_ENTRY_SIZE", 64):
            with self.assertRaises(ValueError):
                _quiet(analyze_apk, self.apk, use_decompiler=False)


class TestSizeLimits(_Fixture):
    def _apk_with(self, name, data):
        path = os.path.join(self.tmp, "extra.apk")
        shutil.copy(self.apk, path)
        with zipfile.ZipFile(path, "a") as zf:
            zf.writestr(name, data)
        return path

    def test_oversized_text_file(self):
        path = self._apk_with("assets/bundle.js", b"var k = 1;\n" * 200)
        with mock.patch.object(apk_mod, "MAX_TEXT_SIZE", 1024):
            result = _quiet(analyze_apk, path, use_decompiler=False)
        item = _skipped(result)["assets/bundle.js"]
        self.assertEqual(item["reason"], coverage.TOO_LARGE)
        self.assertIn("text scan limit", item["detail"])

    def test_oversized_unknown_text_file(self):
        path = self._apk_with("assets/blob.cfg2", b"key=value\n" * 200)
        with mock.patch.object(apk_mod, "MAX_TEXT_SIZE", 1024):
            result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertIn("assets/blob.cfg2", _skipped(result))

    def test_opaque_binary_is_not_a_gap(self):
        path = self._apk_with("assets/model.bin", b"\x00\x01" * 2048)
        with mock.patch.object(apk_mod, "MAX_TEXT_SIZE", 1024):
            result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertNotIn("assets/model.bin", _skipped(result))

    def test_ipa_oversized_text_file(self):
        ipa = build_ipa(self.tmp)
        with zipfile.ZipFile(ipa, "a") as zf:
            zf.writestr("Payload/VulnBank.app/main.jsbundle",
                        b"var k = 1;\n" * 200)
        with mock.patch.object(ipa_mod, "MAX_TEXT_SIZE", 1024):
            result = _quiet(analyze_ipa, ipa)
        self.assertEqual(
            _skipped(result)["Payload/VulnBank.app/main.jsbundle"]["reason"],
            coverage.TOO_LARGE)


class TestFallbackScans(_Fixture):
    def test_invalid_dex_is_degraded_and_still_scanned(self):
        path = os.path.join(self.tmp, "baddex.apk")
        with zipfile.ZipFile(self.apk) as src, \
                zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                data = src.read(info)
                if info.filename == "classes.dex":
                    data = b"NOTDEX" + b"\x00" * 10 + b"AKIAIOSFODNN7EXAMPLE\x00"
                dst.writestr(info, data)
        result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertTrue(result.coverage.complete)
        self.assertEqual([d["file"] for d in result.coverage.degraded],
                         ["classes.dex"])
        self.assertTrue(_from_file(result, "classes.dex"))

    def test_unrecognised_so_is_scanned_as_strings(self):
        path = os.path.join(self.tmp, "badso.apk")
        shutil.copy(self.apk, path)
        name = "lib/arm64-v8a/libhidden.so"
        with zipfile.ZipFile(path, "a") as zf:
            zf.writestr(name, b"\x00\x00JUNK\x00AKIAIOSFODNN7EXAMPLE\x00")
        result = _quiet(analyze_apk, path, use_decompiler=False)
        self.assertIn(name, [d["file"] for d in result.coverage.degraded])
        self.assertTrue(_from_file(result, name))


class TestDirectoryInput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masa_tree_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        with open(os.path.join(self.tmp, "AndroidManifest.xml"), "w") as fh:
            fh.write('<manifest package="com.example.tree"/>')
        with open(os.path.join(self.tmp, "big.js"), "wb") as fh:
            fh.write(b"x" * 4096)
        with open(os.path.join(self.tmp, "icon.png"), "wb") as fh:
            fh.write(b"\x89PNG" + b"\x00" * 8192)

    def test_file_over_limit_is_recorded(self):
        cov = coverage.Coverage()
        files = archive.read_tree(self.tmp, cov, max_size=1024)
        self.assertNotIn("big.js", files)
        self.assertEqual([i["file"] for i in cov.skipped], ["big.js"])
        self.assertEqual(cov.skipped[0]["reason"], coverage.TOO_LARGE)

    def test_media_is_ignored_not_recorded(self):
        cov = coverage.Coverage()
        files = archive.read_tree(self.tmp, cov)
        self.assertNotIn("icon.png", files)
        self.assertEqual(cov.files_seen, 3)
        self.assertTrue(cov.complete)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "root can read any file")
    def test_unreadable_file_is_recorded(self):
        secret = os.path.join(self.tmp, "secret.xml")
        with open(secret, "w") as fh:
            fh.write("<x/>")
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, 0o600)
        cov = coverage.Coverage()
        archive.read_tree(self.tmp, cov)
        self.assertEqual(
            {i["file"]: i["reason"] for i in cov.skipped}["secret.xml"],
            coverage.UNREADABLE)


class TestReports(_Fixture):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix="masa_cov_report_")
        cls.addClassCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = build_apk(tmp)
        _patch(path, "classes.dex", CENTRAL_SIZE, LOCAL_SIZE, "<I", 1)
        result = _quiet(analyze_apk, path, use_decompiler=False)
        cls.report = build_report(result, {"path": path})
        clean_dir = os.path.join(tmp, "clean")
        os.makedirs(clean_dir)
        clean = _quiet(analyze_apk, build_apk(clean_dir), use_decompiler=False)
        cls.clean = build_report(clean, {})

    def test_json(self):
        cov = json.loads(json.dumps(self.report))["coverage"]
        self.assertFalse(cov["complete"])
        self.assertEqual(cov["files_skipped"], 1)

    def test_console(self):
        text = console_summary(self.report)
        self.assertIn("Coverage: INCOMPLETE - 1 of 7 files", text)
        self.assertIn("not analysed: classes.dex", text)
        self.assertIn("Coverage: complete", console_summary(self.clean))

    def test_markdown(self):
        md = _md(self.report)
        self.assertIn("> **Incomplete scan.**", md)
        self.assertIn("| `classes.dex` | unreadable |", md)
        self.assertNotIn("Incomplete scan", _md(self.clean))

    def test_html(self):
        html = _html(self.report)
        self.assertIn('<section class="warn"><h3>Incomplete scan</h3>', html)
        self.assertIn("<code>classes.dex</code>", html)
        self.assertNotIn("Incomplete scan", _html(self.clean))

    def test_sarif(self):
        run = build_sarif(self.report)["runs"][0]
        notes = run["invocations"][0]["toolExecutionNotifications"]
        self.assertEqual(notes[0]["level"], "warning")
        self.assertEqual(notes[0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "classes.dex")
        self.assertFalse(run["properties"]["coverage"]["complete"])
        clean_run = build_sarif(self.clean)["runs"][0]
        self.assertNotIn("toolExecutionNotifications",
                         clean_run["invocations"][0])

    def test_report_without_coverage_attribute(self):
        result = _quiet(analyze_apk, self.apk, use_decompiler=False)
        del result.coverage
        self.assertTrue(build_report(result, {})["coverage"]["complete"])


class TestExitCodes(_Fixture):
    def _run(self, *argv):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            try:
                code = main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, err.getvalue()

    def _forged(self):
        path = self.copy("forged.apk")
        _patch(path, "classes.dex", CENTRAL_SIZE, LOCAL_SIZE, "<I", 1)
        return path

    def test_clean_run(self):
        self.assertEqual(self._run("analyze", self.apk, "--no-decompile")[0],
                         EXIT_OK)

    def test_gate_findings(self):
        code, err = self._run("analyze", self.apk, "--no-decompile",
                              "--fail-on", "high")
        self.assertEqual(code, EXIT_GATE)
        self.assertIn("at or above high", err)

    def test_incomplete_without_strict_passes(self):
        self.assertEqual(self._run("analyze", self._forged(),
                                   "--no-decompile")[0], EXIT_OK)

    def test_strict_fails_incomplete_scan(self):
        code, err = self._run("analyze", self._forged(), "--no-decompile",
                              "--strict")
        self.assertEqual(code, EXIT_GATE)
        self.assertIn("scan incomplete: 1 file(s) not analysed", err)

    def test_strict_passes_complete_scan(self):
        self.assertEqual(self._run("analyze", self.apk, "--no-decompile",
                                   "--strict")[0], EXIT_OK)

    def test_usage_error_is_distinct_from_gate(self):
        self.assertEqual(self._run("analyze", "--bogus")[0], EXIT_ERROR)
        self.assertNotEqual(EXIT_ERROR, EXIT_GATE)

    def test_missing_input(self):
        code, err = self._run("analyze", os.path.join(self.tmp, "nope.apk"))
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)

    def test_no_command(self):
        self.assertEqual(self._run()[0], EXIT_ERROR)

    def test_gate_reports_both_reasons(self):
        report = {"findings": [{"severity": "critical"}],
                  "coverage": {"complete": False, "files_skipped": 2}}
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(gate(report, "critical", strict=True), EXIT_GATE)
        self.assertEqual(err.getvalue().count("gate failed"), 2)


class TestManifestDuplicates(_Fixture):
    def test_structured_finding_is_not_repeated_by_text_scan(self):
        result = _quiet(analyze_apk, self.apk, use_decompiler=False)
        debuggable = [f.file for f in result.findings if f.rule.id == "CFG-004"]
        self.assertEqual(debuggable, ["AndroidManifest.xml"])


class TestHumanSize(unittest.TestCase):
    def test_units(self):
        self.assertEqual(coverage.human_size(512), "512 bytes")
        self.assertEqual(coverage.human_size(8 * 1024 * 1024), "8 MiB")
        self.assertEqual(coverage.human_size(1536), "1.5 KiB")
        self.assertEqual(coverage.human_size(3 * 1024 ** 3), "3 GiB")


if __name__ == "__main__":
    unittest.main()
