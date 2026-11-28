"""masa benchmark: fetch the corpus, scan it, score it against ground truth.

    python bench/run.py           # fetch missing apps, scan, write BENCHMARK.md
    python bench/run.py --check   # also exit 1 if any rule scores worse than
                                  # the committed bench/metrics.json

corpus.json lists the apps (url + sha256; an empty sha256 is filled in on the
first download). truth/<name>.json holds, per app:

    "expected": {"RULE-ID": "why the app has this weakness"}
    "labels":   {"<finding fingerprint>": "tp" | "fp"}

Recall is per (app, expected rule): a hit if the rule fires anywhere in that
app. Precision is per finding: a finding of an expected rule counts as tp
unless labelled fp; any other finding counts only once a human labels it.
Unlabelled findings are reported, so the precision's coverage is visible.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from masa import __version__  # noqa: E402
from masa.apk import analyze_apk  # noqa: E402
from masa.cli import detect_platform  # noqa: E402
from masa.ipa import analyze_ipa  # noqa: E402
from masa.rules import BY_ID  # noqa: E402


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(corpus, apps_dir):
    """Download missing apps and check every app against its pinned sha256.
    Returns True when an empty sha256 was filled in (corpus needs saving)."""
    os.makedirs(apps_dir, exist_ok=True)
    pinned = False
    for app in corpus:
        path = os.path.join(apps_dir, app["name"] + os.path.splitext(
            app["url"])[1])
        app["path"] = path
        if not os.path.exists(path):
            print("fetching %s" % app["url"])
            req = urllib.request.Request(app["url"],
                                         headers={"User-Agent": "masa-bench"})
            with urllib.request.urlopen(req, timeout=120) as resp, \
                    open(path + ".part", "wb") as fh:
                for chunk in iter(lambda: resp.read(1 << 20), b""):
                    fh.write(chunk)
            os.replace(path + ".part", path)
        digest = _sha256(path)
        if not app.get("sha256"):
            app["sha256"] = digest
            pinned = True
            print("pinned %s sha256 %s" % (app["name"], digest))
        elif digest != app["sha256"]:
            raise ValueError("%s: sha256 %s does not match the pinned %s"
                             % (app["name"], digest, app["sha256"]))
    return pinned


def scan(path):
    """Scan one app the way CI would: no decompiler, dex/binary strings only."""
    start = time.monotonic()
    if detect_platform(path) == "android":
        result = analyze_apk(path, use_decompiler=False)
    else:
        result = analyze_ipa(path)
    return {
        "seconds": round(time.monotonic() - start, 1),
        "complete": result.coverage.to_dict()["complete"],
        "findings": [{"rule": f.rule.id, "severity": f.severity,
                      "file": f.file, "snippet": f.snippet[:200],
                      "fingerprint": f.fingerprint()}
                     for f in result.findings],
    }


def load_truth(path):
    truth = {"expected": {}, "labels": {}}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            truth.update(json.load(fh))
    for rule in truth["expected"]:
        if rule not in BY_ID:
            raise ValueError("%s: unknown rule %s" % (path, rule))
    for fp, label in truth["labels"].items():
        if label not in ("tp", "fp"):
            raise ValueError("%s: label for %s must be tp or fp" % (path, fp))
    return truth


def score(results, truths):
    """Per-rule counts: hit/miss (recall) and tp/fp/unlabelled (precision)."""
    rules = {}

    def row(rule):
        return rules.setdefault(rule, {"hit": 0, "miss": 0, "tp": 0, "fp": 0,
                                       "unlabelled": 0})

    for name, res in results.items():
        truth = truths[name]
        fired = {f["rule"] for f in res["findings"]}
        for rule in truth["expected"]:
            row(rule)["hit" if rule in fired else "miss"] += 1
        for f in res["findings"]:
            label = truth["labels"].get(f["fingerprint"])
            if label is None and f["rule"] in truth["expected"]:
                label = "tp"
            row(f["rule"])[label or "unlabelled"] += 1
    return rules


def ratio(a, b):
    return a / (a + b) if a + b else None


def regressions(old, new):
    """Rules whose recall or precision dropped since the committed metrics."""
    out = []
    for rule, before in old.items():
        after = new.get(rule, {"hit": 0, "miss": before["hit"] + before["miss"],
                               "tp": 0, "fp": 0})
        for what, a, b in (("recall", "hit", "miss"), ("precision", "tp", "fp")):
            was, now = ratio(before[a], before[b]), ratio(after[a], after[b])
            if was is not None and (now is None or now < was):
                out.append("%s %s %.2f -> %s" % (
                    rule, what, was, "n/a" if now is None else "%.2f" % now))
    return out


def _pct(a, b):
    r = ratio(a, b)
    return "-" if r is None else "%d%% (%d/%d)" % (round(r * 100), a, a + b)


def markdown(corpus, results, rules):
    tot = {k: sum(r[k] for r in rules.values())
           for k in ("hit", "miss", "tp", "fp", "unlabelled")}
    out = [
        "# masa benchmark", "",
        "masa %s, scanned without a decompiler (dex and binary strings, "
        "resources, manifest), as in CI. Generated by `bench/run.py`; "
        "method in its docstring." % __version__, "",
        "| | |", "|---|---|",
        "| Recall (expected weaknesses found) | %s |" % _pct(tot["hit"],
                                                            tot["miss"]),
        "| Precision (labelled findings) | %s |" % _pct(tot["tp"], tot["fp"]),
        "| Findings not labelled yet | %d |" % tot["unlabelled"], "",
        "## Apps", "",
        "| App | Kind | Findings | Coverage | Seconds |",
        "|---|---|---:|---|---:|",
    ]
    for app in corpus:
        res = results[app["name"]]
        out.append("| %s | %s | %d | %s | %s |" % (
            app["name"], app["kind"], len(res["findings"]),
            "complete" if res["complete"] else "**incomplete**",
            res["seconds"]))
    out += ["", "## Rules", "",
            "| Rule | Title | Recall | Precision | Unlabelled |",
            "|---|---|---|---|---:|"]
    for rule in sorted(rules):
        r = rules[rule]
        out.append("| %s | %s | %s | %s | %d |" % (
            rule, BY_ID[rule].title, _pct(r["hit"], r["miss"]),
            _pct(r["tp"], r["fp"]), r["unlabelled"]))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a rule scores worse than metrics.json")
    args = ap.parse_args(argv)

    corpus_path = os.path.join(HERE, "corpus.json")
    with open(corpus_path, encoding="utf-8") as fh:
        corpus = json.load(fh)
    if fetch(corpus, os.path.join(HERE, "apps")):
        with open(corpus_path, "w", encoding="utf-8") as fh:
            json.dump([{k: v for k, v in a.items() if k != "path"}
                       for a in corpus], fh, indent=2)
            fh.write("\n")

    results, truths = {}, {}
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    for app in corpus:
        print("scanning %s" % app["name"])
        results[app["name"]] = res = scan(app["path"])
        truths[app["name"]] = load_truth(
            os.path.join(HERE, "truth", app["name"] + ".json"))
        # per-finding detail, for labelling: copy fingerprints into truth/
        with open(os.path.join(HERE, "results", app["name"] + ".json"), "w",
                  encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
    rules = score(results, truths)

    metrics_path = os.path.join(HERE, "metrics.json")
    failed = []
    if args.check and os.path.exists(metrics_path):
        with open(metrics_path, encoding="utf-8") as fh:
            failed = regressions(json.load(fh), rules)
    else:
        with open(metrics_path, "w", encoding="utf-8") as fh:
            json.dump(rules, fh, indent=2, sort_keys=True)
            fh.write("\n")
    with open(os.path.join(HERE, "BENCHMARK.md"), "w", encoding="utf-8") as fh:
        fh.write(markdown(corpus, results, rules))
    print("wrote bench/BENCHMARK.md")
    for line in failed:
        print("regression: %s" % line, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
