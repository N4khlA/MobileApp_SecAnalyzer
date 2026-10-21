"""iOS IPA / .app analysis pipeline.

Handles:
  - IPA zip extraction (Payload/*.app) or plain .app directory
  - Info.plist parsing (binary or XML) with ATS analysis
  - Mach-O binary analysis (encryption, strings) incl. frameworks
  - Keychain / NSUserDefaults usage evidence
  - privacy (ATT), entitlements and provisioning checks
"""

import plistlib
import re
import shutil
import struct
import tempfile

from . import archive, native, scanner
from . import plist as bplist
from .apk import AnalysisResult, _dedupe, _rule
from .coverage import TOO_LARGE, human_size, is_media
from .models import Finding, PositiveCheck
from .rules import ALL_RULES

MAX_TEXT_SIZE = 8 * 1024 * 1024
MAX_BINARY_SIZE = 150 * 1024 * 1024

EVIDENCE = {
    "pinning": r"(?i)(TrustKit|CertificatePinner|pinning|"
               r"SecTrustSetAnchorCertificates|ssl[_-]?pinning|"
               r"publicKeyHashes)",
    "secure_random": r"(?i)(SecRandomCopyBytes|getrandom|arc4random|SecureRandom)",
    "aead": r"(?i)(AES/GCM|ChaCha20|AESGCM|/CCM|GCMBlockCipher)",
    "kdf": r"(?i)(PBKDF2|scrypt|Argon2)",
    "keychain": r"(?i)(kSecClassGenericPassword|SecItemAdd|SecItemCopyMatching|"
                r"SecItemUpdate|KeychainSwift|KeychainWrapper)",
    "biometric": r"(?i)(LAContext|LocalAuthentication|BiometricPrompt|FaceID|"
                 r"biometricAuthentication)",
    "root_detection": r"(?i)(jailbroken|isJailbroken|JBDetection|RootBeer|"
                      r"detectRoot|frida)",
    "obfuscation": r"(?i)(ios-ssl-kill-switch|obfuscat|xor[_-]?string)",
}

ABSENCE_RULES = {"BIN-002": "obfuscation", "BIN-003": "root_detection"}


def _load_files(input_path, coverage):
    return archive.load(input_path, coverage, MAX_BINARY_SIZE)


def _skip_large(result, name, size, limit, what):
    result.coverage.skip(name, TOO_LARGE, "%s exceeds the %s %s limit"
                         % (human_size(size), human_size(limit), what))


def _find_app_dir(files):
    """Locate the .app bundle directory name (or None for bare dirs)."""
    candidates = []
    for name in files:
        if name.endswith(".app/Info.plist"):
            candidates.append(name[:name.rfind("/Info.plist")])
        elif name == "Info.plist":
            candidates.append("")
    if not candidates:
        return None
    return max(candidates, key=len)


def _parse_plist(data):
    try:
        return plistlib.loads(data)
    except (plistlib.InvalidPlistException, ValueError, KeyError, OSError, TypeError):
        try:
            return bplist.loads(bytes(data))
        except (ValueError, KeyError, OSError, TypeError, struct.error):
            return None


def _nested(d, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def analyze_ipa(input_path, out_dir=None):
    """Analyze an IPA file or iOS .app directory."""
    result = AnalysisResult()
    result.platform = "ios"
    work = tempfile.mkdtemp(prefix="masa_ipa_")
    try:
        files = _load_files(input_path, result.coverage)
        if not files:
            raise ValueError("could not read input (not a zip and not a directory)")

        app_dir = _find_app_dir(files)
        if app_dir is None:
            raise ValueError("no .app bundle found (Info.plist missing)")

        prefix = app_dir + "/" if app_dir else ""
        plist_path = prefix + "Info.plist"
        info = _parse_plist(files.get(plist_path, b"")) or {}
        result.summary = {
            "bundle_id": info.get("CFBundleIdentifier"),
            "bundle_name": info.get("CFBundleName"),
            "bundle_version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
            "minimum_os": info.get("MinimumOSVersion"),
            "platforms": info.get("CFBundleSupportedPlatforms"),
        }
        result.app_name = info.get("CFBundleIdentifier") or \
            info.get("CFBundleName")

        findings = []
        scanner_ = scanner.Scanner(ALL_RULES)

        # ---- Info.plist / config checks ----
        _plist_checks(result, findings, info, plist_path)

        # ---- text files ----
        text_files = []
        binaries = []
        for name, data in files.items():
            low = name.lower()
            if len(data) > MAX_BINARY_SIZE:
                _skip_large(result, name, len(data), MAX_BINARY_SIZE, "file")
                continue
            if scanner.is_text_ext(low):
                if len(data) > MAX_TEXT_SIZE:
                    _skip_large(result, name, len(data), MAX_TEXT_SIZE,
                                "text scan")
                    continue
                text_files.append((name, scanner.decode_text(data)))
            elif is_media(low) or low.endswith((".dylib", ".a")):
                continue
            else:
                info_struct, f = native.analyze_binary(data, name)
                if info_struct:
                    binaries.append((name, info_struct))
                    findings.extend(f)
                    scanner_.scan_strings(info_struct.get("strings", []),
                                          name, findings)
                elif b"\x00" not in data[:4096]:
                    if len(data) > MAX_TEXT_SIZE:
                        _skip_large(result, name, len(data), MAX_TEXT_SIZE,
                                    "text scan")
                        continue
                    text_files.append((name, scanner.decode_text(data)))

        scanner_.scan_all(text_files, findings)
        result.binaries = [{"file": n, "info": i} for n, i in binaries]

        # ---- provisioning profile / entitlements ----
        for name, data in files.items():
            low = name.lower()
            if low.endswith(".mobileprovision"):
                txt = scanner.decode_text(data)
                mobileprov = _parse_plist(data) or {}
                _provision_checks(result, findings, mobileprov, txt, name)
            elif low.endswith(".plist") and name != plist_path:
                p = _parse_plist(data)
                if isinstance(p, dict):
                    _plist_checks(result, findings, p, name, extra=True)

        # ---- evidence pool ----
        pool = "\n".join(c for _n, c in text_files)
        for name, info_struct in binaries:
            pool += "\n" + "\n".join(info_struct.get("strings", []))
        for key, pattern in EVIDENCE.items():
            if re.search(pattern, pool):
                result.positives.append(PositiveCheck(key, key, "found"))

        for rid, ev_key in ABSENCE_RULES.items():
            if not any(p.key == ev_key for p in result.positives):
                findings.append(Finding(_rule(rid), file="(app)",
                                        evidence_type="behavior",
                                        extra={"absent": True}))

        result.findings = _dedupe(findings)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _plist_checks(result, findings, info, plist_path, extra=False):
    ats = _nested(info, "NSAppTransportSecurity")
    if isinstance(ats, dict):
        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append(Finding(_rule("NET-011"), file=plist_path,
                                    evidence_type="config"))
        if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            result.notes.append(
                "ATS: NSAllowsArbitraryLoadsInWebContent=true (WebKit "
                "exemptions) in %s" % plist_path)
        domains = ats.get("NSExceptionDomains")
        if isinstance(domains, dict):
            for domain, cfg in domains.items():
                if isinstance(cfg, dict) and \
                        cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    findings.append(Finding(_rule("NET-016"), file=plist_path,
                                            evidence_type="config",
                                            extra={"domain": domain}))

    min_os = info.get("MinimumOSVersion")
    if min_os:
        try:
            major = int(str(min_os).split(".")[0])
            if major < 14:
                findings.append(Finding(_rule("SCP-004"), file=plist_path,
                                        evidence_type="config",
                                        extra={"MinimumOSVersion": min_os}))
        except (TypeError, ValueError):
            pass

    if info.get("NSUserTrackingUsageDescription"):
        result.positives.append(PositiveCheck(
            "att_consent", "ATT usage description present", plist_path))


def _provision_checks(result, findings, profile, text, name):
    if not isinstance(profile, dict):
        return
    entitlements = profile.get("Entitlements") or {}
    if entitlements.get("get-task-allow") is True:
        findings.append(Finding(_rule("CFG-004"), file=name,
                                evidence_type="config",
                                extra={"attribute": "get-task-allow=true"}))
    if entitlements.get("aps-environment"):
        result.notes.append("APS environment: %s" %
                            entitlements["aps-environment"])
    exp = profile.get("ExpirationDate")
    if exp:
        result.summary["provision_expiry"] = str(exp)
    for key in ("application-identifier", "com.apple.developer.team-identifier"):
        if entitlements.get(key):
            result.summary.setdefault("entitlements", {})[key] = \
                entitlements[key]
