"""Android APK / source-tree analysis pipeline.

Handles:
  - APK zip extraction, or plain directory (apktool output / source tree)
  - AndroidManifest.xml parsing (binary AXML or plain XML)
  - component / intent-filter / permission analysis
  - resource, dex string-table and native (.so) scanning
  - optional apktool/jadx decompilation when installed
"""

import json
import os
import re
import shutil
import struct
import tempfile
import zipfile
from xml.etree import ElementTree as ET

from . import archive, axml, decompile, dex, native, scanner
from .coverage import TOO_LARGE, UNREADABLE, Coverage, human_size
from .models import Finding, PositiveCheck, Rule
from .rules import ALL_RULES, BY_ID

ANDROID_NS = "http://schemas.android.com/apk/res/android"

MAX_TEXT_SIZE = 8 * 1024 * 1024
MANIFEST_VIEW = "AndroidManifest.xml (normalized)"

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
    "pinning": (r"(?i)(CertificatePinner|TrustKit|pinning|<pin-set\b|"
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
    "screen_protection": (r"FLAG_SECURE|setRecentsScreenshotEnabled\s*\(\s*"
                          r"false|isSecureTextEntry|secureTextEntry"),
}

# rules that are evidence-based (emit when evidence NOT found)
_SHORT_CLASS = re.compile(r"^L(?:[\w$]+/)+[a-z]{1,2};$")
_TELEPHONY_ID = re.compile(r"getDeviceId|getImei|getSubscriberId|getSimSerialNumber")
_PHONE_STATE = {"android.permission.READ_PHONE_STATE",
                "android.permission.READ_PRIVILEGED_PHONE_STATE"}

ABSENCE_RULES = {"BIN-002": "obfuscation", "BIN-003": "root_detection",
                 "PRI-005": "screen_protection"}

# biometric prompt used as a yes/no gate instead of unlocking a key
_BIOMETRIC_GATE = (
    ("android", r"\b(?:BiometricPrompt|FingerprintManager)\b",
     r"\bauthenticate\b", r"\bCryptoObject\b"),
    ("ios", r"\bLAContext\b", r"\bevaluatePolicy\b",
     r"SecAccessControlCreateWithFlags|kSecAttrAccessControl|"
     r"\.biometry(?:CurrentSet|Any)\b|kSecAccessControlBiometry"),
)


def biometric_binding_finding(pool):
    """ATH-003 when biometrics are used but never bound to a key."""
    for platform, api, call, binding in _BIOMETRIC_GATE:
        if re.search(api, pool) and re.search(call, pool) and \
                not re.search(binding, pool):
            return Finding(_rule("ATH-003"), file="(app)",
                           evidence_type="behavior",
                           extra={"platform": platform})
    return None


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
        self.components = []     # dicts, see _parse_components()
        self.custom_permissions = {}  # <permission> name -> protection level
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


COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver",
                  "provider")
PROTECTION_LEVELS = {0: "normal", 1: "dangerous", 2: "signature",
                     3: "signatureOrSystem"}


def _tag(el):
    """Local tag name for an AXML or ElementTree element."""
    if hasattr(el, "attrs"):
        return el.name
    return el.tag.split("}")[-1]


def _attr(el, name):
    if hasattr(el, "attrs"):
        return el.get(name)
    return _aval(el, name)


def _kids(el):
    return el.children if hasattr(el, "attrs") else list(el)


def protection_level(value):
    """Normalize android:protectionLevel (string flags or AXML int) to its
    base level: normal, dangerous, signature or signatureOrSystem."""
    if value is None:
        return "normal"
    if isinstance(value, int) or str(value).strip().lstrip("-").isdigit() \
            or str(value).strip().lower().startswith("0x"):
        try:
            num = value if isinstance(value, int) else int(str(value), 0)
        except ValueError:
            return str(value)
        return PROTECTION_LEVELS.get(num & 0xF, "normal")
    base = str(value).split("|")[0].strip()
    return base or "normal"


def _parse_components(app_el):
    comps = []
    for child in _kids(app_el):
        kind = _tag(child)
        if kind not in COMPONENT_TAGS:
            continue
        actions, categories, grants = [], [], []
        for sub in _kids(child):
            stag = _tag(sub)
            if stag == "intent-filter":
                for item in _kids(sub):
                    itag = _tag(item)
                    if itag == "action" and _attr(item, "name"):
                        actions.append(_attr(item, "name"))
                    elif itag == "category" and _attr(item, "name"):
                        categories.append(_attr(item, "name"))
            elif stag == "grant-uri-permission":
                grants.append({k: _attr(sub, k) for k in
                               ("path", "pathPrefix", "pathPattern")
                               if _attr(sub, k) is not None})
        exported = _attr(child, "exported")
        if exported is None:
            exported = bool(actions)
        else:
            exported = bool(_bval(exported))
        comps.append({
            "type": kind, "name": _attr(child, "name") or "?",
            "exported": exported,
            "permission": _attr(child, "permission"),
            "read_permission": _attr(child, "readPermission"),
            "write_permission": _attr(child, "writePermission"),
            "grant_uri_permissions": bool(_bval(_attr(child,
                                                      "grantUriPermissions"))),
            "uri_grants": grants,
            "actions": actions,
            "categories": categories,
        })
    return comps


def _parse_custom_permissions(manifest_el):
    out = {}
    for el in _kids(manifest_el):
        if _tag(el) == "permission" and _attr(el, "name"):
            out[_attr(el, "name")] = protection_level(
                _attr(el, "protectionLevel"))
    return out


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
    info.package = m.get("package", ns=None)   # no android: prefix
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
    info.custom_permissions = _parse_custom_permissions(m)
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
        info.components = _parse_components(app)
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
    info.custom_permissions = _parse_custom_permissions(m)
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
            info.components = _parse_components(el)
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
        self.manifest_path = "AndroidManifest.xml"
        self.coverage = Coverage()


def _load_files(input_path, coverage):
    """Return {relpath: bytes} from a zip (APK) or a directory tree."""
    return archive.load(input_path, coverage)


def _find_manifest(files):
    """Return the path of the app manifest: the archive root for APKs and
    apktool output, otherwise the best match in a source tree (Gradle
    src/main first, build outputs last)."""
    if "AndroidManifest.xml" in files:
        return "AndroidManifest.xml"
    cands = [n for n in files
             if n.replace("\\", "/").rsplit("/", 1)[-1] == "AndroidManifest.xml"]
    if not cands:
        return None

    def rank(name):
        parts = name.replace("\\", "/").split("/")
        return ("build" in parts, "src/main/" not in "/".join(parts),
                len(parts), name)
    return min(cands, key=rank)


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.rule.id, f.file, f.line)
        if f.line is None and f.extra:
            # manifest/behavior findings have no line; keep one per component,
            # permission, etc. instead of collapsing them all into one
            key += (json.dumps(f.extra, sort_keys=True, default=str),)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _drop_manifest_view_duplicates(findings):
    """Drop text-scan hits on the normalized manifest that a structured check
    already reported on the real AndroidManifest.xml."""
    structured = {f.rule.id for f in findings if f.evidence_type == "manifest"}
    return [f for f in findings
            if not (f.file == MANIFEST_VIEW and f.rule.id in structured)]


def _rule(id_):
    r = BY_ID.get(id_)
    if r:
        return Rule(id_, r.title, r.severity, r.owasp, r.category,
                    description=r.description, remediation=r.remediation)
    return Rule(id_, id_, "medium", "M8", "config")


def _skip_large(result, name, size):
    result.coverage.skip(name, TOO_LARGE, "%s exceeds the %s text scan limit"
                         % (human_size(size), human_size(MAX_TEXT_SIZE)))


def analyze_apk(input_path, out_dir=None, use_decompiler=True):
    """Analyze an APK file or Android project directory."""
    result = AnalysisResult()
    work = tempfile.mkdtemp(prefix="masa_apk_")
    try:
        files = _load_files(input_path, result.coverage)
        if not files:
            raise ValueError("could not read input (not a zip/apk and not a directory)")

        # ---- manifest ----
        manifest_path = _find_manifest(files)
        if manifest_path is None:
            raise ValueError("AndroidManifest.xml not found in input")
        manifest_raw = files[manifest_path]
        result.manifest_path = manifest_path
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
                    _skip_large(result, name, len(data))
                    continue
                text_files.append((name, scanner.decode_text(data)))
            elif low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp",
                               ".arsc", ".otf", ".ttf")):
                continue
            elif b"\x00" not in data[:4096]:
                if len(data) > MAX_TEXT_SIZE:
                    _skip_large(result, name, len(data))
                    continue
                text_files.append((name, scanner.decode_text(data)))
        text_files.append((MANIFEST_VIEW,
                           result.manifest.dump_xml()))

        scanner_.scan_all(text_files, findings)

        # ---- dex string tables ----
        dex_ok = 0
        for name, blob in dex_blobs:
            strings = dex.dex_strings(blob)
            if not strings:
                strings = dex.extract_naive(blob, 5)
                result.coverage.degrade(
                    name, "not a valid dex file; scanned raw strings instead")
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
                scanner_.scan_strings(native.extract_strings(blob), name,
                                      findings)
                result.coverage.degrade(
                    name, "not a recognized ELF binary; scanned raw strings "
                          "instead")

        # ---- optional decompilation ----
        decompiled_extra = []
        tools = {}
        is_zip_input = zipfile.is_zipfile(input_path)
        if use_decompiler and is_zip_input and not any(
                n.endswith((".java", ".smali")) for n in files):
            tools = decompile.available_tools()
            if tools:
                ddir = os.path.join(work, "decompiled")
                ok = decompile.decompile_apk(input_path, ddir, tools)
                if ok:
                    result.notes.append("decompiled with %s" % ok)
                    for dirpath, _d, fns in os.walk(ddir):
                        for fn in fns:
                            full = os.path.join(dirpath, fn)
                            rel = "decompiled/" + os.path.relpath(full, ddir)
                            if fn.endswith((".java", ".smali", ".kt")):
                                try:
                                    with open(full, "rb") as fh:
                                        data = fh.read()
                                    if len(data) > MAX_TEXT_SIZE:
                                        _skip_large(result, rel, len(data))
                                        continue
                                    decompiled_extra.append(
                                        (rel, scanner.decode_text(data)))
                                except OSError as exc:
                                    result.coverage.skip(
                                        rel, UNREADABLE, str(exc))
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
        # R8/ProGuard leaves 1-2 letter class names (Lsg/vantagepoint/a/a;)
        if not any(p.key == "obfuscation" for p in result.positives) and sum(
                1 for s in all_strings if _SHORT_CLASS.match(s)) >= 3:
            result.positives.append(PositiveCheck(
                "obfuscation", "obfuscation", "short class names"))

        # absence-based rules
        for rid, ev_key in ABSENCE_RULES.items():
            if not any(p.key == ev_key for p in result.positives):
                findings.append(Finding(_rule(rid), file="(app)",
                                        evidence_type="behavior",
                                        extra={"absent": True}))

        # ---- manifest-driven programmatic checks ----
        _manifest_checks(result, findings, files)
        _permission_checks(result, findings, evidence_pool)
        if is_zip_input:
            _signing_checks(result, findings, input_path)
        biometric = biometric_binding_finding(evidence_pool)
        if biometric:
            findings.append(biometric)
        # telephony IDs need READ_PHONE_STATE; without it the call only throws
        if not _PHONE_STATE & set(result.manifest.permissions):
            findings = [f for f in findings if not (
                f.rule.id == "PRI-001" and _TELEPHONY_ID.search(f.snippet))]
        findings = _drop_manifest_view_duplicates(_dedupe(findings))
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
        findings.append(Finding(_rule("CFG-004"), file=result.manifest_path,
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
        findings.append(Finding(_rule("CFG-002"), file=result.manifest_path,
                                evidence_type="manifest"))
    elif m.app.get("allowBackup") is None and not has_rules:
        findings.append(Finding(_rule("CFG-003"), file=result.manifest_path,
                                evidence_type="manifest"))

    if _bval(m.uses_cleartext):
        findings.append(Finding(_rule("NET-002"), file=result.manifest_path,
                                evidence_type="manifest"))
    if m.network_config:
        ref = m.network_config.split("/")[-1]
        for name, data in files.items():
            if name.endswith(ref + ".xml") or name.endswith("/" + ref + ".xml"):
                _network_config_checks(scanner.decode_text(data), name,
                                       findings)
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
                findings.append(Finding(r, file=result.manifest_path,
                                        evidence_type="manifest",
                                        extra={"targetSdk": m.target_sdk}))
        except (TypeError, ValueError):
            pass

    _component_checks(result, findings)


LAUNCHER = ("android.intent.action.MAIN", "android.intent.category.LAUNCHER")
WEAK_LEVELS = ("normal", "dangerous")
BROAD_GRANTS = {"path": ("/",), "pathPrefix": ("", "/"),
                "pathPattern": (".*", "/.*", ".*/.*")}


def _is_launcher_only(comp):
    """The launcher activity has to be exported; flag it only when it also
    accepts other actions (deep links, custom actions)."""
    return (comp["type"] in ("activity", "activity-alias") and
            LAUNCHER[1] in comp.get("categories", []) and
            set(comp["actions"]) <= {LAUNCHER[0]})


def _component_checks(result, findings):
    m = result.manifest
    where = result.manifest_path

    def add(rule_id, comp, **extra):
        data = {"component": comp["name"], "type": comp["type"]}
        data.update(extra)
        findings.append(Finding(_rule(rule_id), file=where,
                                evidence_type="manifest", extra=data))

    for name, level in sorted(m.custom_permissions.items()):
        if level == "signatureOrSystem":
            findings.append(Finding(_rule("CFG-008"), file=where,
                                    evidence_type="manifest",
                                    extra={"permission": name}))

    for comp in m.components:
        perm = comp.get("permission")
        read = comp.get("read_permission")
        write = comp.get("write_permission")

        for grant in comp.get("uri_grants", []):
            for attr, bad in BROAD_GRANTS.items():
                if attr in grant and grant[attr] in bad:
                    add("CFG-009", comp, grant="%s=%r" % (attr, grant[attr]))

        if not comp["exported"]:
            continue
        if comp["type"] == "provider":
            if not (perm or read or write):
                add("CFG-001", comp, actions=comp["actions"])
            elif not perm and not (read and write):
                add("CFG-006", comp,
                    missing="writePermission" if read else "readPermission")
        elif not perm and not _is_launcher_only(comp):
            add("CFG-001", comp, actions=comp["actions"])

        for guard in {g for g in (perm, read, write) if g}:
            level = m.custom_permissions.get(guard)
            if level in WEAK_LEVELS:
                add("CFG-007", comp, permission=guard, level=level)


def _network_config_checks(txt, name, findings):
    # <debug-overrides> only applies to debuggable builds
    release = re.sub(r"(?is)<debug-overrides\b.*?</debug-overrides>", "", txt)
    if re.search(r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']", release):
        findings.append(Finding(_rule("NET-003"), file=name,
                                evidence_type="config"))
    if re.search(r"<certificates\s[^>]*src\s*=\s*[\"']user[\"']", release):
        findings.append(Finding(_rule("NET-017"), file=name,
                                evidence_type="config"))


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V1_SIGNATURE = re.compile(r"(?i)^META-INF/[^/]+\.(?:RSA|DSA|EC)$")


def apk_signing_schemes(path):
    """Return {"v1": bool, "v2plus": bool} for an APK, or None if the
    input is not a readable zip. v2/v3/v4 all live in the APK Signing
    Block that sits right before the zip central directory."""
    try:
        with zipfile.ZipFile(path) as zf:
            v1 = any(V1_SIGNATURE.match(n) for n in zf.namelist())
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            tail_len = min(size, 65536 + 22)
            fh.seek(size - tail_len)
            tail = fh.read()
            eocd = tail.rfind(b"PK\x05\x06")
            v2 = False
            if eocd >= 0 and eocd + 20 <= len(tail):
                cd_offset = struct.unpack_from("<I", tail, eocd + 16)[0]
                if cd_offset >= 16:
                    fh.seek(cd_offset - 16)
                    v2 = fh.read(16) == APK_SIG_BLOCK_MAGIC
    except (OSError, zipfile.BadZipFile, struct.error):
        return None
    return {"v1": v1, "v2plus": v2}


def _signing_checks(result, findings, input_path):
    schemes = apk_signing_schemes(input_path)
    if schemes is None:
        return
    result.summary["signing"] = schemes
    if not schemes["v1"] and not schemes["v2plus"]:
        findings.append(Finding(_rule("BIN-006"), file="(apk)",
                                evidence_type="binary"))
        return
    if schemes["v1"] and not schemes["v2plus"]:
        r = _rule("BIN-005")
        try:
            min_sdk = int(str(result.manifest.min_sdk))
        except (TypeError, ValueError):
            min_sdk = None
        if min_sdk is not None and min_sdk >= 24:
            r.severity = "medium"
        findings.append(Finding(r, file="(apk)", evidence_type="binary",
                                extra={"minSdk": result.manifest.min_sdk}))


def _permission_checks(result, findings, evidence_pool):
    perms = set(result.manifest.permissions)
    for perm, (what, keyword, severity) in DANGEROUS.items():
        if perm not in perms:
            continue
        r = _rule("PERM-001")
        r.severity = severity
        findings.append(Finding(r, file=result.manifest_path,
                                evidence_type="manifest",
                                extra={"permission": perm, "what": what}))
        if not re.search(keyword, evidence_pool):
            findings.append(Finding(_rule("PERM-002"),
                                    file=result.manifest_path,
                                    evidence_type="manifest",
                                    extra={"permission": perm, "what": what}))
    for perm, what in HIGH_RISK_PERMS.items():
        if perm in perms:
            findings.append(Finding(_rule("PERM-004"),
                                    file=result.manifest_path,
                                    evidence_type="manifest",
                                    extra={"permission": perm, "what": what}))
    for label, severity, combo in DANGER_COMBOS:
        if all(c in perms for c in combo):
            r = _rule("PERM-003")
            r.severity = severity
            findings.append(Finding(r, file=result.manifest_path,
                                    evidence_type="manifest",
                                    extra={"combo": label,
                                           "permissions": combo}))
