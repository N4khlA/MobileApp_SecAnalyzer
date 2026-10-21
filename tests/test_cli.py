"""Tests for the CLI gate, SARIF output and archive limits."""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from masa import archive  # noqa: E402
from masa.apk import analyze_apk  # noqa: E402
from masa.cli import detect_platform, main  # noqa: E402
from masa.report import build_report, build_sarif, write_sarif  # noqa: E402
from masa.rules import ALL_RULES  # noqa: E402
from masa.samples import build_apk  # noqa: E402


class _FakeZip:
    def __init__(self, infos):
        self.infos = infos

    def infolist(self):
        return self.infos


class TestDetectPlatform(unittest.TestCase):
    def test_app_substring_in_path_is_not_ios(self):
        tmp = tempfile.mkdtemp(prefix="masa_detect_")
        with self.assertRaises(ValueError):
            detect_platform(os.path.join(tmp, "my.app.backup"))

    def test_app_bundle_directory(self):
        tmp = tempfile.mkdtemp(prefix="masa_detect_")
        app = os.path.join(tmp, "Demo.app")
        os.mkdir(app)
        self.assertEqual(detect_platform(app), "ios")

    def test_android_project_directory(self):
        tmp = tempfile.mkdtemp(prefix="masa_detect_")
        with open(os.path.join(tmp, "AndroidManifest.xml"), "w") as fh:
            fh.write("<manifest/>")
        self.assertEqual(detect_platform(tmp), "android")


class TestArchiveLimit(unittest.TestCase):
    def test_entry_too_large(self):
        info = zipfile.ZipInfo("huge.bin")
        info.file_size = archive.MAX_ENTRY_SIZE + 1
        with self.assertRaises(ValueError):
            archive.check_zip(_FakeZip([info]))

    def test_total_too_large(self):
        infos = []
        for i in range(5):
            info = zipfile.ZipInfo("part%d.bin" % i)
            info.file_size = archive.MAX_ENTRY_SIZE - 1
            infos.append(info)
        with self.assertRaises(ValueError):
            archive.check_zip(_FakeZip(infos))

    def test_normal_archive(self):
        info = zipfile.ZipInfo("classes.dex")
        info.file_size = 1024
        archive.check_zip(_FakeZip([info]))


class TestSarif(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masa_sarif_")
        cls.apk = build_apk(cls.tmp)
        result = analyze_apk(cls.apk, use_decompiler=False)
        rules = [r.to_dict() for r in ALL_RULES]
        cls.report = build_report(result, {"path": cls.apk, "sha256": "x"},
                                  rules)

    def test_document(self):
        doc = build_sarif(self.report)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", doc["$schema"])
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "masa")
        self.assertTrue(run["results"])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], ids)
            self.assertIn(result["level"], ("error", "warning", "note"))
            self.assertIn("masa/v1", result["partialFingerprints"])
        net = [r for r in run["results"] if r["ruleId"] == "NET-004"][0]
        self.assertEqual(net["level"], "error")
        self.assertIn("locations", net)

    def test_write(self):
        path = os.path.join(self.tmp, "out.sarif")
        write_sarif(self.report, path)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])


class TestCliGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masa_gate_")
        cls.apk = build_apk(cls.tmp)

    def _run(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            return main(["analyze", self.apk, "--no-decompile"] + list(args))

    def test_fail_on_critical(self):
        self.assertEqual(self._run("--fail-on", "critical"), 2)

    def test_fail_on_none(self):
        self.assertEqual(self._run("--fail-on", "none"), 0)

    def test_sarif_flag(self):
        path = os.path.join(self.tmp, "nested", "gate.sarif")
        self.assertEqual(self._run("--sarif", path), 0)
        self.assertTrue(os.path.getsize(path) > 1000)

    def test_version(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as err, redirect_stdout(out):
            main(["--version"])
        self.assertEqual(err.exception.code, 0)
        self.assertIn("masa 1.1.0", out.getvalue())


if __name__ == "__main__":
    unittest.main()
