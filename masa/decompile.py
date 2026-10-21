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


def available_tools():
    found = {}
    for tool in ("apktool", "jadx", "d2j-dex2jar", "dex2jar", "java",
                 "cfr", "radare2", "r2", "ghidra"):
        path = which(tool)
        if path:
            found[tool] = path
    return found


def _run(cmd, timeout=600):
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              text=True)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def decompile_apk(apk_path, out_dir):
    """Try apktool then jadx to obtain readable source. Returns True on
    success (source appears under out_dir)."""
    tools = available_tools()
    if "apktool" in tools:
        if _run([tools["apktool"], "d", "-f", "-o", out_dir, apk_path]):
            return True
    if "jadx" in tools:
        try:
            jadx_bin = tools["jadx"]
            if os.name == "nt" and not jadx_bin.lower().endswith(".bat"):
                jadx_bin = jadx_bin + ".bat"
            if _run([jadx_bin, "-d", out_dir, apk_path]):
                return True
        except OSError:
            pass
    return False


def dex_to_java(classes_dex, work_dir):
    """dex2jar + CFR pipeline for a single classes.dex (if java present).
    Returns the output jar path or None."""
    tools = available_tools()
    if "d2j-dex2jar" in tools and "java" in tools:
        jar = os.path.join(work_dir, "classes.jar")
        if _run([tools["d2j-dex2jar"], "-o", jar, classes_dex]):
            return jar
    return None
