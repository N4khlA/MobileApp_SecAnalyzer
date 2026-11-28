"""Scan the benchmark corpus with a local MobSF, for bench/COMPARISON.md.

    python bench/mobsf.py [APP ...]   # default: every app in corpus.json
    python bench/mobsf.py --suffix noskip InsecureBankv2   # -> InsecureBankv2.noskip.json

Needs MobSF on http://127.0.0.1:8000 with its REST API key in ~/.mobsf_key
(see bench/COMPARISON.md). Reports go to bench/mobsf/<app>.json, with the
scan time; apps that already have a report are skipped.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "http://127.0.0.1:8000/api/v1/"
OUT = os.path.join(HERE, "mobsf")


def _key():
    with open(os.path.expanduser("~/.mobsf_key")) as fh:
        return fh.read().strip()


def _call(endpoint, key, data=None, files=None, timeout=1800):
    headers = {"Authorization": key, "X-Mobsf-Api-Key": key}
    if files:
        boundary = uuid.uuid4().hex
        body = b""
        for name, (filename, content) in files.items():
            body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
                     "filename=\"%s\"\r\nContent-Type: application/octet-stream"
                     "\r\n\r\n" % (boundary, name, filename)).encode()
            body += content + b"\r\n"
        body += ("--%s--\r\n" % boundary).encode()
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    else:
        body = urllib.parse.urlencode(data or {}).encode()
    req = urllib.request.Request(URL + endpoint, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def scan(path, key):
    with open(path, "rb") as fh:
        up = _call("upload", key, files={"file": (os.path.basename(path), fh.read())})
    start = time.monotonic()
    _call("scan", key, data={"hash": up["hash"], "re_scan": "1"})
    seconds = round(time.monotonic() - start, 1)
    report = _call("report_json", key, data={"hash": up["hash"]})
    report["_bench"] = {"seconds": seconds, "hash": up["hash"]}
    return report


def main(argv=None):
    names = list(argv if argv is not None else sys.argv[1:])
    suffix = ""
    if names[:1] == ["--suffix"]:
        suffix, names = "." + names[1], names[2:]
    key = _key()
    with open(os.path.join(HERE, "corpus.json")) as fh:
        corpus = json.load(fh)
    os.makedirs(OUT, exist_ok=True)
    for app in corpus:
        if names and app["name"] not in names:
            continue
        out = os.path.join(OUT, app["name"] + suffix + ".json")
        if os.path.exists(out):
            continue
        path = os.path.join(HERE, "apps", app["name"] + os.path.splitext(app["url"])[1])
        print("mobsf %s" % app["name"], flush=True)
        try:
            report = scan(path, key)
        except Exception as exc:  # keep going; the comparison lists failures
            print("  failed: %s" % exc, flush=True)
            report = {"_bench": {"error": str(exc)}}
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        print("  %ss" % report["_bench"].get("seconds", "-"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
