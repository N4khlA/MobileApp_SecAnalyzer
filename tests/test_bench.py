"""Offline test of bench/run.py: the built-in sample stands in for the corpus."""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "bench"))

import run  # noqa: E402
from masa.samples import build_apk  # noqa: E402


class TestBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masa_bench_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        src = build_apk(cls.tmp)
        cls.app = {"name": "sample", "kind": "vulnerable",
                   "url": "file://" + src, "sha256": ""}
        corpus = [dict(cls.app)]
        with contextlib.redirect_stdout(io.StringIO()):
            cls.pinned = run.fetch(corpus, os.path.join(cls.tmp, "apps"))
        cls.app = corpus[0]
        cls.result = run.scan(cls.app["path"])

    def test_fetch_pins_then_verifies(self):
        self.assertTrue(self.pinned)
        self.assertEqual(len(self.app["sha256"]), 64)
        bad = [dict(self.app, sha256="0" * 64)]
        with self.assertRaises(ValueError):
            run.fetch(bad, os.path.join(self.tmp, "apps"))

    def test_scan_records_findings_with_fingerprints(self):
        self.assertTrue(self.result["complete"])
        self.assertTrue(self.result["findings"])
        self.assertTrue(all(len(f["fingerprint"]) == 12
                            for f in self.result["findings"]))

    def test_score(self):
        sec = next(f for f in self.result["findings"] if f["rule"] == "SEC-001")
        net = next(f for f in self.result["findings"] if f["rule"] == "NET-001")
        truth = {"expected": {"SEC-001": "planted", "STO-008": "iOS only"},
                 "labels": {sec["fingerprint"]: "fp", net["fingerprint"]: "tp"}}
        rules = run.score({"sample": self.result}, {"sample": truth})
        self.assertEqual(rules["SEC-001"]["hit"], 1)
        self.assertEqual(rules["STO-008"]["miss"], 1)   # never fires on an APK
        n_sec = sum(f["rule"] == "SEC-001" for f in self.result["findings"])
        self.assertEqual(rules["SEC-001"]["fp"], 1)
        self.assertEqual(rules["SEC-001"]["tp"], n_sec - 1)  # rest auto-tp
        self.assertEqual(rules["NET-001"]["tp"], 1)
        self.assertGreater(rules["NET-001"]["unlabelled"], 0)
        md = run.markdown([self.app], {"sample": self.result}, rules)
        self.assertIn("| SEC-001 |", md)

    def test_regressions(self):
        old = {"A": {"hit": 2, "miss": 0, "tp": 4, "fp": 0, "unlabelled": 0}}
        same = {"A": dict(old["A"], unlabelled=3)}
        self.assertEqual(run.regressions(old, same), [])
        worse = {"A": {"hit": 1, "miss": 1, "tp": 4, "fp": 1, "unlabelled": 0}}
        self.assertEqual(len(run.regressions(old, worse)), 2)
        # a rule that stops firing loses its recall and its precision
        self.assertEqual(len(run.regressions(old, {})), 2)

    def test_fdroid_archive_fallback(self):
        import urllib.error
        from unittest import mock
        calls = []

        def fake_open(url):
            calls.append(url)
            if "/repo/" in url or "example.org" in url:
                raise urllib.error.HTTPError(url, 404, "gone", {}, None)
            return io.BytesIO(b"apk bytes")
        path = os.path.join(self.tmp, "moved.apk")
        with mock.patch.object(run, "_open", fake_open), \
                contextlib.redirect_stdout(io.StringIO()):
            run._download("https://f-droid.org/repo/x_1.apk", path)
            with self.assertRaises(urllib.error.HTTPError):   # no fallback
                run._download("https://example.org/x.apk", path + "2")
        self.assertEqual(calls[:2], ["https://f-droid.org/repo/x_1.apk",
                                     "https://f-droid.org/archive/x_1.apk"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"apk bytes")

    def test_truth_files_are_valid(self):
        truth_dir = os.path.join(os.path.dirname(HERE), "bench", "truth")
        for name in os.listdir(truth_dir):
            with self.subTest(name):
                run.load_truth(os.path.join(truth_dir, name))


if __name__ == "__main__":
    unittest.main()
