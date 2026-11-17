"""Optional decompiler integration (apktool / jadx / dex2jar+CFR).

These tools are used when present on PATH. When they are not available the
analyzer degrades gracefully: manifest + resources are parsed natively and
dex string tables are recovered (see masa.dex).
"""

import os
import shutil
import subprocess


def which(cmd):
    return shutil.which(cmd)


CFR_JAR_ENV = "MASA_CFR_JAR"


def available_tools():
    found = {}
    for tool in ("apktool", "jadx", "d2j-dex2jar", "dex2jar", "java",
                 "cfr", "cfr-decompiler", "radare2", "r2", "ghidra"):
        path = which(tool)
        if path:
            found[tool] = path
    jar = os.environ.get(CFR_JAR_ENV)
    if jar and os.path.isfile(jar):
        found["cfr.jar"] = jar
    return found


def _run(cmd, timeout=600):
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              text=True)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _has_sources(out_dir, exts=(".java", ".smali", ".kt")):
    for _dirpath, _dirs, files in os.walk(out_dir):
        if any(f.endswith(exts) for f in files):
            return True
    return False


def _cfr_command(tools):
    """Command prefix that runs CFR: a `cfr` wrapper on PATH, or
    `java -jar $MASA_CFR_JAR`."""
    for name in ("cfr", "cfr-decompiler"):
        if name in tools:
            return [tools[name]]
    if "cfr.jar" in tools and "java" in tools:
        return [tools["java"], "-jar", tools["cfr.jar"]]
    return None


def _jadx(tools, apk_path, out_dir):
    jadx_bin = tools["jadx"]
    if os.name == "nt" and not jadx_bin.lower().endswith(".bat"):
        jadx_bin = jadx_bin + ".bat"
    return _run([jadx_bin, "-d", out_dir, apk_path])


def _dex2jar_cfr(tools, apk_path, out_dir):
    dex2jar = tools.get("d2j-dex2jar") or tools.get("dex2jar")
    cfr = _cfr_command(tools)
    if not dex2jar or not cfr:
        return False
    os.makedirs(out_dir, exist_ok=True)
    jar = os.path.join(out_dir, "classes-dex2jar.jar")
    if not _run([dex2jar, "-f", "-o", jar, apk_path]):
        return False
    return _run(cfr + [jar, "--outputdir", out_dir])


def _apktool(tools, apk_path, out_dir):
    return _run([tools["apktool"], "d", "-f", "-o", out_dir, apk_path])


# Java source first: the text rules are written against Java/Kotlin, and
# apktool only yields smali.
PIPELINE = (("jadx", _jadx), ("dex2jar+cfr", _dex2jar_cfr),
            ("apktool", _apktool))


def decompile_apk(apk_path, out_dir, tools=None):
    """Decompile with the first tool that produces sources: jadx, then
    dex2jar+CFR, then apktool. Returns the name of the pipeline used, or
    None when nothing worked."""
    tools = available_tools() if tools is None else tools
    for name, step in PIPELINE:
        needed = name.split("+")[0]
        if needed == "dex2jar":
            if not (tools.get("d2j-dex2jar") or tools.get("dex2jar")):
                continue
        elif needed not in tools:
            continue
        try:
            if step(tools, apk_path, out_dir) and _has_sources(out_dir):
                return name
        except OSError:
            continue
    return None
