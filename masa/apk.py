"""Android APK / source-tree analysis pipeline.

Handles:
  - APK zip extraction, or plain directory (apktool output / source tree)
  - AndroidManifest.xml parsing (binary AXML or plain XML)
  - component / intent-filter / permission analysis
  - resource, dex string-table and native (.so) scanning
  - optional apktool/jadx decompilation when installed
"""

import os
import re
import shutil
import tempfile
import zipfile
from xml.etree import ElementTree as ET

from . import axml, decompile, dex, native, scanner
from .models import Finding, PositiveCheck, Rule
from .rules import ALL_RULES, BY_ID, get_rule

ANDROID_NS = "http://schemas.android.com/apk/res/android"

MAX_TEXT_SIZE = 8 * 1024 * 1024

# dangerous-protection-level permissions and their usage keywords
DANGEROUS = {
    "android.permission.CAMERA": (
        "camera/microphone", r"(?i)\b(camera|MediaRecorder|takePicture|Camera2|"
        r"CameraManager|imageCapture)\b", "medium"),
    "android.permission.RECORD_AUDIO": (
        "microphone", r"(?i)\b(MediaRecorder|AudioRecord|recordAudio|"
        r"startRecording|AudioManager)\b", "medium"),
    "android.permission.ACCESS_FINE_LOCATION": (
        "precise location", r"(?i)\b(LocationManager|FusedLocation|"
        r"getLastKnownLocation|requestLocationUpdates|Geofence|geolocation)"
        r"\b", "medium"),
    "android.permission.ACCESS_COARSE_LOCATION": (
        "approximate location", r"(?i)\b(LocationManager|FusedLocation|"
        r"requestLocationUpdates|Geocoder|geolocation)\b", "low"),
    "android.permission.READ_CONTACTS": (
        "contacts", r"(?i)\b(ContactsContract|RawContacts|getContacts|"
        r"ContactPicker|CNContact)\b", "medium"),
    "android.permission.WRITE_CONTACTS": (
        "contacts write", r"(?i)\b(ContactsContract|RawContacts|"
        r"insert.*contact|ContactEditor)\b", "medium"),
    "android.permission.READ_SMS": (
        "SMS read", r"(?i)\b(SmsManager|Telephony\.Sms|SmsMessage|"
        r"SMS_RECEIVED)\b", "high"),
    "android.permission.SEND_SMS": (
        "SMS send", r"(?i)\b(SmsManager|sendTextMessage|sendDataMessage)"
        r"\b", "medium"),
    "android.permission.RECEIVE_SMS": (
        "SMS receive", r"(?i)\b(SMS_RECEIVED|SmsMessage|"
        r"android\.provider\.Telephony\.SMS)\b", "high"),
    "android.permission.READ_CALL_LOG": (
        "call log", r"(?i)\b(CallLog|callLog|READ_CALL_LOG)\b", "high"),
    "android.permission.WRITE_CALL_LOG": (
        "call log write", r"(?i)\b(CallLog)\b", "medium"),
    "android.permission.READ_PHONE_STATE": (
        "phone state", r"(?i)\b(TelephonyManager|getDeviceId|getSubscriberId|"
        r"getSimSerialNumber|PhoneStateListener)\b", "medium"),
    "android.permission.CALL_PHONE": (
        "phone calls", r"(?i)\b(ACTION_CALL|Intent\.ACTION_CALL|TelecomManager"
        r"|tel:)\b", "medium"),
    "android.permission.BODY_SENSORS": (
        "health sensors", r"(?i)\b(SensorManager|Sensor\.TYPE_HEART|"
        r"BodySensor)\b", "medium"),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "external storage", r"(?i)\b(getExternalStorage|MediaStore|"
        r"ACTION_OPEN_DOCUMENT)\b", "low"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "external storage write", r"(?i)\b(getExternalStorage|MediaStore)"
        r"\b", "low"),
    "android.permission.READ_MEDIA_IMAGES": (
        "photo library", r"(?i)\b(MediaStore|PickVisualMedia|getContentResolver)"
        r"\b", "low"),
    "android.permission.READ_MEDIA_VIDEO": (
        "video library", r"(?i)\b(MediaStore)\b", "low"),
    "android.permission.READ_MEDIA_AUDIO": (
        "audio library", r"(?i)\b(MediaStore)\b", "low"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "background location", r"(?i)\b(LocationManager|FusedLocation)\b",
        "high"),
}

HIGH_RISK_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install packages",
    "android.permission.QUERY_ALL_PACKAGES": "query all packages",
    "android.permission.WRITE_SETTINGS": "modify system settings",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "manage all files",
    "android.permission.BIND_DEVICE_ADMIN": "device administration",
}

DANGER_COMBOS = [
    ("Stalking suite: camera + microphone + location", "high",
     ["android.permission.CAMERA", "android.permission.RECORD_AUDIO",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.ACCESS_COARSE_LOCATION"]),
    ("SMS fraud suite: SMS + call log + phone state", "high",
     ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
      "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
      "android.permission.READ_PHONE_STATE"]),
    ("Full profile harvesting: contacts + SMS + call log", "high",
     ["android.permission.READ_CONTACTS", "android.permission.READ_SMS",
      "android.permission.READ_CALL_LOG"]),
    ("Contact exfiltration: contacts + network", "medium",
     ["android.permission.READ_CONTACTS", "android.permission.INTERNET"]),
    ("Location tracking without need: location + background location", "medium",
     ["android.permission.ACCESS_FINE_LOCATION",
      "android.permission.ACCESS_BACKGROUND_LOCATION"]),
]

# positive security evidence regexes
EVIDENCE = {
    "pinning": (r"(?i)(CertificatePinner|TrustKit|pinning|"
                r"SecTrustSetAnchorCertificates|ssl[_-]?pinning|publicKeyHashes)"),
    "secure_random": (r"(?i)(SecureRandom|SecRandomCopyBytes|getrandom|"
                      r"arc4random)"),
    "aead": r"(?i)(AES/GCM|AES_256_GCM|ChaCha20|AESGCM|/CCM)",
    "kdf": r"(?i)(PBKDF2|scrypt|Argon2|Argon2id)",
    "keystore": (r"(?i)(AndroidKeyStore|EncryptedSharedPreferences|"
                 r"KeyChain\.|kSecClassGenericPassword|SecItemAdd|"
                 r"KeychainSwift|KeychainHelper|KeyStore\s*\.\s*getInstance)"),
    "sqlcipher": r"(?i)(SQLCipher|net\.zetetic)",
    "obfuscation": r"(?i)(minifyEnabled|isMinifyEnabled|\bR8\b|ProGuard|proguard-rules|obfuscate)",
    "root_detection": (r"(?i)(RootBeer|isRooted|detectRoot|rootDetection|"
                       r"jailbroken|isJailbroken|FridaServer|tamperDetection)"),
    "biometric": (r"(?i)(BiometricPrompt|FingerprintManager|LocalAuthentication|"
                  r"LAContext|FaceID|biometricPrompt)"),
    "consent": (r"(?i)(consent|OptIn|opt-in|privacy[_-]?policy|PrivacyPolicy|"
                r"ConsentInformation|requestConsent)"),
    "keychain": r"(?i)(kSecClassGenericPassword|SecItemAdd|SecItemCopyMatching|Keychain)",
    "https_only": r"(?i)https://",
}

# rules that are evidence-based (emit when evidence NOT found)
ABSENCE_RULES = {"BIN-002": "obfuscation", "BIN-003": "root_detection"}


class ManifestInfo:
    """Normalized AndroidManifest model (from AXML or plain XML)."""

    def __init__(self):
        self.package = None
        self.version_code = None
        self.version_name = None
        self.min_sdk = None
        self.target_sdk = None
        self.compile_sdk = None
        self.permissions = []
        self.features = []
        self.components = []     # dicts: type/name/exported/permission/actions
        self.queries = []
        self.app = {}            # application-level attributes
        self.backup_rules_file = None
        self.uses_cleartext = None
        self.network_config = None
        self.is_axml = False

    def dump_xml(self):
        """Normalized text form for regex scanning."""
        lines = ['<?xml version="1.0" encoding="utf-8"?>',
                 '<manifest package="%s" versionCode="%s" versionName="%s">'
                 % (self.package, self.version_code, self.version_name)]
        lines.append("  <uses-sdk minSdkVersion=\"%s\" targetSdkVersion=\"%s\"/>"
                     % (self.min_sdk, self.target_sdk))
        for p in self.permissions:
            lines.append('  <uses-permission android:name="%s"/>' % p)
        app = self.app or {}
        lines.append('  <application android:allowBackup="%s" '
                     'android:debuggable="%s" android:usesCleartextTraffic="%s"/>'
                     % (app.get("allowBackup", "?"), app.get("debuggable", "?"),
                        app.get("usesCleartextTraffic", "?")))
        for c in self.components:
            lines.append('  <%s android:name="%s" android:exported="%s"'
                         % (c["type"], c["name"], c["exported"]))
            if c.get("permission"):
                lines[-1] += ' android:permission="%s"' % c["permission"]
            lines[-1] += ">"
            for a in c.get("actions", []):
                lines.append('    <intent-filter><action android:name="%s"/>'
                             '</intent-filter>' % a)
            lines.append("  </%s>" % c["type"])
        lines.append("</manifest>")
        return "\n".join(lines)


# ------------------------------------------------------------------ manifest

def _aval(el, name, default=None):
    for key, val in (el.attrib or {}).items():
        if key == name:
            return val
        if key.endswith("}%s" % name):
            return val
    return default


def parse_manifest_bytes(data):
    """Parse AndroidManifest bytes (AXML or XML) into ManifestInfo."""
    if axml.looks_like_axml(data):
        root = axml.parse(data)
        info = _manifest_from_axml(root)
        info.is_axml = True
        return info
    return _manifest_from_xml(data)


def _manifest_from_axml(root):
    info = ManifestInfo()
    m = root.find("manifest")
    if m is None:
        m = root
    info.package = m.get("package", None)
    info.version_code = m.get("versionCode", None)
    info.version_name = m.get("versionName", None)
    sdk = m.find("uses-sdk")
    if sdk is not None:
        info.min_sdk = sdk.get("minSdkVersion")
        info.target_sdk = sdk.get("targetSdkVersion")
    for up in m.findall("uses-permission"):
        name = up.get("name")
        if name:
            info.permissions.append(name)
    for uf in m.findall("uses-feature"):
        name = uf.get("name")
        if name:
            info.features.append(name)
    for q in m.findall("queries"):
        info.queries.append(q.to_xml())
    app = m.find("application")
    if app is not None:
        for key in ("allowBackup", "debuggable", "usesCleartextTraffic",
                    "networkSecurityConfig", "fullBackupContent", "label",
                    "icon", "backupAgent", "dataExtractionRules"):
            v = app.get(key)
            if v is not None:
                info.app[key] = v
        info.uses_cleartext = app.get("usesCleartextTraffic")
        info.network_config = app.get("networkSecurityConfig")
        for kind in ("activity", "activity-alias", "service", "receiver",
                     "provider"):
            for el in app.findall(kind):
                comp = {
                    "type": kind, "name": el.get("name", "?"),
                    "exported": el.get("exported", None),
                    "permission": el.get("permission", None),
                    "actions": [a.get("name") for a in el.findall(
                        "intent-filter") for a in a.findall("action")],
                }
                if comp["exported"] is None:
                    comp["exported"] = bool(comp["actions"])
                info.components.append(comp)
    return info


def _manifest_from_xml(data):
    info = ManifestInfo()
    root = ET.fromstring(data)
    m = root if root.tag.endswith("manifest") else None
    if m is None:
        raise ValueError("no <manifest> element found")
    def v(el, name):
        return _aval(el, name)
    info.package = v(m, "package")
    info.version_code = v(m, "versionCode")
    info.version_name = v(m, "versionName")
    for el in m:
        tag = el.tag.split("}")[-1]
        if tag == "uses-sdk":
            info.min_sdk = v(el, "minSdkVersion")
            info.target_sdk = v(el, "targetSdkVersion")
        elif tag == "uses-permission":
            name = v(el, "name")
            if name:
                info.permissions.append(name)
        elif tag == "uses-feature":
            name = v(el, "name")
            if name:
                info.features.append(name)
        elif tag == "application":
            for key in ("allowBackup", "debuggable", "usesCleartextTraffic",
                        "networkSecurityConfig", "fullBackupContent", "label",
                        "icon", "backupAgent", "dataExtractionRules"):
                val = v(el, key)
                if val is not None:
                    info.app[key] = val
            info.uses_cleartext = v(el, "usesCleartextTraffic")
            info.network_config = v(el, "networkSecurityConfig")
            for child in el:
                ctag = child.tag.split("}")[-1]
                if ctag not in ("activity", "activity-alias", "service",
                                "receiver", "provider"):
                    continue
                actions = []
                for filt in child:
                    if filt.tag.split("}")[-1] == "intent-filter":
                        for a in filt:
                            if a.tag.split("}")[-1] == "action":
                                actions.append(v(a, "name"))
                exported = v(child, "exported")
                if exported is None:
                    exported = bool(actions)
                info.components.append({
                    "type": ctag, "name": v(child, "name") or "?",
                    "exported": exported,
                    "permission": v(child, "permission"),
                    "actions": actions,
                })
    return info


# ------------------------------------------------------------------ analysis

class AnalysisResult:
    def __init__(self):
        self.platform = "android"
        self.manifest = None
        self.findings = []
        self.positives = []
        self.summary = {}
        self.notes = []
        self.app_name = None
        self.binaries = []
        self.permission_audit = []


def _load_files(input_path):
    """Return {relpath: bytes} from a zip (APK) or a directory tree."""
    files = {}
    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path) as zf:
            for name in zf.namelist():
                try:
                    files[name] = zf.read(name)
                except (KeyError, zipfile.BadZipFile):
                    continue
    else:
        for dirpath, dirnames, filenames in os.walk(input_path):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, input_path)
                try:
                    size = os.path.getsize(full)
                    if size > MAX_TEXT_SIZE and not fn.endswith((".dex", ".so")):
                        continue
                    with open(full, "rb") as fh:
                        files[rel] = fh.read()
                except OSError:
                    continue
    return files


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.rule.id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _rule(id_):
    r = BY_ID.get(id_)
    if r:
        return Rule(id_, r.title, r.severity, r.owasp, r.category,
                    description=r.description, remediation=r.remediation)
    return Rule(id_, id_, "medium", "M8", "config")


def analyze_apk(input_path, out_dir=None, use_decompiler=True):
    """Analyze an APK file or Android project directory."""
    result = AnalysisResult()
    work = tempfile.mkdtemp(prefix="masa_apk_")
    try:
        files = _load_files(input_path)
        if not files:
            raise ValueError("could not read input (not a zip/apk and not a directory)")

        # ---- manifest ----
        manifest_raw = files.get("AndroidManifest.xml")
        if manifest_raw is None:
            raise ValueError("AndroidManifest.xml not found in input")
        result.manifest = parse_manifest_bytes(manifest_raw)
        result.app_name = result.manifest.package
        result.summary = {
            "package": result.manifest.package,
            "versionName": result.manifest.version_name,
            "versionCode": result.manifest.version_code,
            "minSdk": result.manifest.min_sdk,
            "targetSdk": result.manifest.target_sdk,
            "permissions_declared": len(result.manifest.permissions),
            "components": len(result.manifest.components),
        }

        # ---- text files for scanning ----
        scanner_ = scanner.Scanner(ALL_RULES)
        findings = []
        text_files = []
        dex_blobs = []
        so_blobs = []
        for name, data in files.items():
            low = name.lower()
            if low.endswith(".dex"):
                dex_blobs.append((name, data))
            elif low.endswith(".so"):
                so_blobs.append((name, data))
            elif scanner.is_text_ext(low):
                if len(data) > MAX_TEXT_SIZE:
                    result.notes.append("skipped oversized text file: %s" % name)
                    continue
                text_files.append((name, scanner.decode_text(data)))
            elif low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp",
                               ".arsc", ".otf", ".ttf")):
                continue
            elif len(data) <= MAX_TEXT_SIZE and b"\x00" not in data[:4096]:
                text_files.append((name, scanner.decode_text(data)))
        text_files.append(("AndroidManifest.xml (normalized)",
                           result.manifest.dump_xml()))

        scanner_.scan_all(text_files, findings)

        # ---- dex string tables ----
        dex_ok = 0
        for name, blob in dex_blobs:
            strings = dex.dex_strings(blob)
            if not strings:
                strings = dex.extract_naive(blob, 5)
                result.notes.append("%s: not a valid dex, used raw string scan"
                                    % name)
            else:
                dex_ok += 1
            scanner_.scan_strings(strings, name, findings)

        # ---- native libraries ----
        for name, blob in so_blobs:
            info, f = native.analyze_binary(blob, name)
            findings.extend(f)
            if info:
                result.binaries.append({"file": name, "info": info})
                scanner_.scan_strings(info.get("strings", []), name, findings)
            else:
                result.notes.append("%s: not a recognized ELF binary" % name)

        # ---- optional decompilation ----
        decompiled_extra = []
        tools = {}
        is_zip_input = zipfile.is_zipfile(input_path)
        if use_decompiler and is_zip_input and not any(
                n.endswith((".java", ".smali")) for n in files):
            tools = decompile.available_tools()
            if tools:
                ddir = os.path.join(work, "decompiled")
                ok = decompile.decompile_apk(input_path, ddir)
                if ok:
                    for dirpath, _d, fns in os.walk(ddir):
                        for fn in fns:
                            full = os.path.join(dirpath, fn)
                            rel = "decompiled/" + os.path.relpath(full, ddir)
                            if fn.endswith((".java", ".smali", ".kt")):
                                try:
                                    with open(full, "rb") as fh:
                                        data = fh.read()
                                    if len(data) <= MAX_TEXT_SIZE:
                                        decompiled_extra.append(
                                            (rel, scanner.decode_text(data)))
                                except OSError:
                                    continue
        scanner_.scan_all(decompiled_extra, findings)
        if tools:
            result.notes.append("decompilers available: %s" %
                                ", ".join(sorted(tools)))
        else:
            result.notes.append(
                "no decompiler found on PATH (apktool/jadx); used dex string "
                "table + resources instead")

        # ---- evidence / positive checks ----
        all_text = "\n".join(c for _n, c in text_files) + "\n" + \
            "\n".join(c for _n, c in decompiled_extra)
        all_strings = []
        for name, blob in dex_blobs:
            all_strings.extend(dex.dex_strings(blob) or
                               dex.extract_naive(blob, 5))
        for name, blob in so_blobs:
            all_strings.extend(native.extract_strings(blob))
        evidence_pool = all_text + "\n" + "\n".join(all_strings)

        for key, pattern in EVIDENCE.items():
            if re.search(pattern, evidence_pool):
                result.positives.append(PositiveCheck(key, key, "found"))

        # absence-based rules
        for rid, ev_key in ABSENCE_RULES.items():
            if not any(p.key == ev_key for p in result.positives):
                findings.append(Finding(_rule(rid), file="(app)",
                                        evidence_type="behavior",
                                        extra={"absent": True}))

        # ---- manifest-driven programmatic checks ----
        _manifest_checks(result, findings, files)
        _permission_checks(result, findings, evidence_pool)
        findings = _dedupe(findings)
        result.findings = findings
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _bval(v):
    if v is None:
        return None
    return str(v).strip().lower() in ("true", "1")


def _manifest_checks(result, findings, files):
    m = result.manifest
    if _bval(m.app.get("debuggable")):
        findings.append(Finding(_rule("CFG-004"), file="AndroidManifest.xml",
                                evidence_type="manifest",
                                extra={"attribute": "debuggable=true"}))
    allow_backup = _bval(m.app.get("allowBackup"))
    has_rules = bool(m.app.get("fullBackupContent") or
                     m.app.get("dataExtractionRules") or
                     m.backup_rules_file)
    if not has_rules:
        for name in files:
            if re.search(r"backup", name, re.I) and name.endswith(".xml"):
                has_rules = True
                m.backup_rules_file = name
                break
    if allow_backup:
        findings.append(Finding(_rule("CFG-002"), file="AndroidManifest.xml",
                                evidence_type="manifest"))
    elif m.app.get("allowBackup") is None and not has_rules:
        findings.append(Finding(_rule("CFG-003"), file="AndroidManifest.xml",
                                evidence_type="manifest"))

    if _bval(m.uses_cleartext):
        findings.append(Finding(_rule("NET-002"), file="AndroidManifest.xml",
                                evidence_type="manifest"))
    if m.network_config:
        ref = m.network_config.split("/")[-1]
        for name, data in files.items():
            if name.endswith(ref + ".xml") or name.endswith("/" + ref + ".xml"):
                txt = scanner.decode_text(data)
                if re.search(r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']",
                             txt):
                    findings.append(Finding(_rule("NET-003"), file=name,
                                            evidence_type="config"))
                break

    target = m.target_sdk
    if target is not None:
        try:
            target = int(str(target))
            sev = "high" if target < 28 else ("medium" if target < 30 else
                                              "low")
            if sev != "low":
                r = _rule("SCP-001")
                r.severity = sev
                findings.append(Finding(r, file="AndroidManifest.xml",
                                        evidence_type="manifest",
                                        extra={"targetSdk": m.target_sdk}))
        except (TypeError, ValueError):
            pass

    for comp in m.components:
        if comp["exported"] and not comp.get("permission"):
            if comp["type"] == "provider" or comp["actions"]:
                findings.append(Finding(_rule("CFG-001"),
                                        file="AndroidManifest.xml",
                                        evidence_type="manifest",
                                        extra={
                                            "component": comp["name"],
                                            "type": comp["type"],
                                            "actions": comp["actions"]}))


def _permission_checks(result, findings, evidence_pool):
    perms = set(result.manifest.permissions)
    for perm, (what, keyword, severity) in DANGEROUS.items():
        if perm not in perms:
            continue
        r = _rule("PERM-001")
        r.severity = severity
        findings.append(Finding(r, file="AndroidManifest.xml",
                                evidence_type="manifest",
                                extra={"permission": perm, "what": what}))
        if not re.search(keyword, evidence_pool):
            findings.append(Finding(_rule("PERM-002"),
                                    file="AndroidManifest.xml",
                                    evidence_type="manifest",
                                    extra={"permission": perm, "what": what}))
    for perm, what in HIGH_RISK_PERMS.items():
        if perm in perms:
            findings.append(Finding(_rule("PERM-004"),
                                    file="AndroidManifest.xml",
                                    evidence_type="manifest",
                                    extra={"permission": perm, "what": what}))
    for label, severity, combo in DANGER_COMBOS:
        if all(c in perms for c in combo):
            r = _rule("PERM-003")
            r.severity = severity
            findings.append(Finding(r, file="AndroidManifest.xml",
                                    evidence_type="manifest",
                                    extra={"combo": label,
                                           "permissions": combo}))
