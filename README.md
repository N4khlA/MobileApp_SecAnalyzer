# Mobile App Security Analyzer (`masa`)

[![ci](https://github.com/N4khlA/MobileApp_SecAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/N4khlA/MobileApp_SecAnalyzer/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP Mobile Top 10](https://img.shields.io/badge/OWASP-Mobile%20Top%2010%20(2023)-red.svg)](https://owasp.org/www-project-mobile-top-10/)

`masa` is a lightweight, **zero-dependency** (Python standard library only) static security scanner for **Android (APK, source tree)** and **iOS (IPA, `.app` bundle)** applications.

It automatically evaluates application binaries and source code against the **OWASP Mobile Top 10 (2023 revision)** with backwards-compatible **2016 legacy mappings**, generating rich terminal summaries, JSON data exports, Markdown reports, and styled HTML dashboards.

---

## Key Features

- **Zero External Dependencies**: Runs strictly on Python 3 standard library (`zipfile`, `xml.etree`, `plistlib`, `re`, `struct`).
- **Android & iOS Support**:
  - **Android**: Parses binary AXML (`AndroidManifest.xml`), DEX string tables, resource files, and ELF `.so` native libraries.
  - **iOS**: Parses binary/XML `Info.plist`, ATS configurations, `.mobileprovision` profiles, and Mach-O executables/frameworks.
- **Native String Scanning**: fast regex-based string extraction from native binaries.
- **Android IPC Checks**: intent redirection, mutable implicit PendingIntents, sticky broadcasts, spoofable caller checks, unflagged dynamic receivers, weak custom permissions and root-wide URI grants.
- **Binary Hardening**: PIE, RELRO, NX stack and stack canaries on ELF; encryption, stack canaries and ARC on Mach-O; APK signature scheme (v1-only / Janus).
- **OWASP Mobile Top 10 Compliance**: Scores app posture across all 10 categories (M1-M10) with positive security control detection (Keystore, Keychain, AEAD ciphers, Biometrics, Pinning).
- **Optional Decompiler Integration**: When an APK has no sources, masa tries `jadx`, then `dex2jar` + CFR, then `apktool` (smali), using whichever is on `PATH`. CFR is found as a `cfr` wrapper or via `MASA_CFR_JAR=/path/to/cfr.jar`.
- **Multi-Format Reporting**: Generates interactive HTML dashboards, Markdown summaries, structured JSON reports and SARIF 2.1.0 for code scanning.
- **CI Gate**: `--fail-on` turns findings into a non-zero exit code, so a pipeline can block on critical or high severity issues.
- **Adoptable in CI**: inline `masa-ignore` comments and a `.masa.toml` for accepted findings, plus `--baseline` so only new findings fail the build. Ships as a GitHub Action.
- **CWE + MASVS v2 ids** on every rule, in every report format and as SARIF tags.
- **File-type scoping**: API-call rules skip config and docs, and native rules only look at native code, which cuts duplicate and misplaced findings.

---

## Installation

### From PyPI
```bash
pip install masa-scan    # installs the `masa` command
```

### From Source
```bash
git clone https://github.com/N4khlA/MobileApp_SecAnalyzer.git
cd MobileApp_SecAnalyzer
pip install .
```

### Development / Editable Mode
```bash
pip install -e ".[dev]"
```

---

## Usage

### 1. Run the Demo
Build vulnerable sample Android (`.apk`) and iOS (`.ipa`) fixtures and analyze them end-to-end:
```bash
masa demo
```
or via Python module:
```bash
python -m masa demo
```

### 2. Analyze an Application
```bash
# Analyze an Android APK
masa analyze path/to/app.apk -o output_dir/

# Analyze an iOS IPA
masa analyze path/to/app.ipa -o output_dir/

# Analyze an unpacked directory (apktool output or a Gradle project;
# the manifest is found at the root or under src/main/)
masa analyze path/to/AndroidProject/ -o output_dir/
```

### 3. List Detection Rules
```bash
# List all active security rules
masa rules

# Filter rules by category (secrets, crypto, storage, network, ipc, auth,
# config, privacy, native, etc.)
masa rules --category crypto
```

---

## CI Integration

Write SARIF for GitHub code scanning and fail the build on serious findings:

```bash
masa analyze app.apk -o reports/ --sarif reports/masa.sarif --fail-on high --strict
```

```yaml
- name: Scan APK
  run: masa analyze app.apk --sarif masa.sarif --fail-on high --strict
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: masa.sarif
```

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - run: ./gradlew assembleRelease
  - uses: N4khlA/MobileApp_SecAnalyzer@v1.3.0
    with:
      target: app/build/outputs/apk/release/app-release.apk
      fail-on: high
      # args: --baseline masa-baseline.json   # only new findings fail
```

Inputs: `target` (required), `fail-on` (default `high`), `sarif` (default
`masa.sarif`), `upload-sarif` (default `true`) and `args` for any other
`masa analyze` flags, such as `--baseline masa-baseline.json --strict`. SARIF is uploaded before the gate is
applied, so the alerts are visible even when the job fails.

### Suppressing findings

Accept a finding in code, on its line or on a comment line directly above:

```java
String key = "AKIAIOSFODNN7EXAMPLE"; // masa-ignore: SEC-001 -- AWS docs example key
// masa-ignore: CRY-002 -- MD5 is only a cache key here
String k = md5(url);
```

`masa-ignore` with no ids silences every rule on that line. For findings
without a line (manifest, binary and behaviour checks) or for whole folders,
use `.masa.toml` (Python 3.11+) or `.masa.json` in the directory you run
masa from, or pass `--config PATH`:

```toml
[[ignore]]
rule = "SEC-002"
path = "res/values/*.xml"
reason = "Maps key restricted to our package + signing cert"

[[ignore]]
path = "assets/vendor/*"
reason = "third-party SDK, tracked upstream"
```

Each entry needs a `reason`, plus a `rule`, a `path` or both. Suppressed
findings are listed under `suppressed` in the JSON report and carry SARIF
`suppressions`. They do not fail the gate or lower the grade.

### Baselines

To adopt masa on an existing app without fixing everything first, save a
report once and gate only on what is new:

```bash
masa analyze app.apk -o reports/                  # writes reports/app.report.json
cp reports/app.report.json masa-baseline.json     # commit this
masa analyze app.apk --baseline masa-baseline.json --fail-on high
```

Findings are matched by a fingerprint (rule, file, snippet) that ignores
line numbers, so moving code around does not create "new" findings. Known
findings stay in the report as `baselined` and still count toward the OWASP
grade, which describes the app rather than the diff.

| Exit code | Meaning |
|---|---|
| `0` | Scan finished and passed the gate |
| `1` | Gate failed: a finding at or above `--fail-on`, or an incomplete scan with `--strict` |
| `2` | Error: bad arguments, or input that could not be analysed |

`--fail-on` accepts `critical`, `high`, `medium`, `low`, `info` or `none`
(default). The reason for a failed gate is printed to stderr.

### Scan coverage

A scanner that silently drops a file reports fewer findings than the app really
has. masa records every file it could not analyse (corrupt, encrypted or
forged zip entries, unsupported compression, files over the size limits, unreadable
files) and every file it could only scan as raw strings (invalid dex, unrecognised
native libraries). Each report shows this:

- **Console and Markdown:** a `Coverage: INCOMPLETE` line or banner listing the files.
- **HTML:** an "Incomplete scan" section above the executive summary.
- **JSON:** a `coverage` object with `complete`, `files_seen`, `skipped` and `degraded`.
- **SARIF:** `toolExecutionNotifications` on the invocation, plus `run.properties.coverage`.

Add `--strict` to fail the build when coverage is incomplete. Media files (images,
audio, fonts) are never scanned and do not count as gaps.

### SARIF locations

Results point at paths *inside the analysed app* (for example `classes.dex` or
`res/values/strings.xml`), not at files in your repository. GitHub shows the alerts,
but the file links only resolve when you scan a source tree that is checked in.

This is a static analyzer. It does not replace dynamic testing, and a clean
scan is not proof that an app is secure.

---

## OWASP Mobile Top 10 (2023) Coverage

| OWASP Category | Name | Detection Scope |
|---|---|---|
| **M1** | Improper Credential Usage | Hardcoded AWS keys, Google API keys, Stripe secret keys, JWTs, private keys, passwords |
| **M2** | Inadequate Supply Chain Security | Deprecated Apache HTTP client, dynamic code loading (`DexClassLoader`), low target SDKs |
| **M3** | Insecure Authentication/Authorization | Client-side authorization checks, intent redirection, mutable implicit PendingIntents, sticky broadcasts, `checkCallingOrSelfPermission`, caller identity from Intent extras, dynamic receivers without an export flag, biometrics not bound to a key, custom URL schemes |
| **M4** | Insufficient Input/Output Validation | SQL injection (`rawQuery`), path traversal, dangerous WebView JavaScript bridges |
| **M5** | Insecure Communication | Cleartext HTTP URLs, ATS bypasses, `TrustAll` certificate manager overrides, hostname verification bypasses, user-installed CAs trusted in `network_security_config.xml`, WebView JavaScript |
| **M6** | Inadequate Privacy Protections | PII/credential logging in logcat/NSLog, hardware ID harvesting (IMEI/MAC), ATT prompt checks, secrets on the clipboard, missing `FLAG_SECURE` |
| **M7** | Insufficient Binary Protections | Unsafe string functions in native code (`strcpy`, `sprintf`), non-PIE binaries, missing RELRO, executable stack, missing stack canaries, Objective-C without ARC, unencrypted Mach-O, v1-only APK signing |
| **M8** | Security Misconfiguration | Debuggable builds, backup enabled without rules (`allowBackup=true`), staging endpoints, exported components without permission, providers missing read or write permission, weak or deprecated custom protection levels, root-wide `grant-uri-permission` |
| **M9** | Insecure Data Storage | Plaintext SharedPreferences, `NSUserDefaults` token storage, world-readable/writable files, `kSecAttrAccessibleAlways` Keychain items, files without Data Protection |
| **M10** | Insufficient Cryptography | DES/3DES, MD5, SHA-1, RC4, ECB encryption mode, hardcoded IVs, seeded PRNGs |

---

## Architecture Overview

```
masa/
├── __init__.py       # Version and package metadata
├── __main__.py       # Package CLI execution entry point
├── cli.py            # Argument parsing and subcommand handler
├── apk.py            # Android APK / source tree pipeline
├── ipa.py            # iOS IPA / .app bundle pipeline
├── axml.py           # Dependency-free Binary AXML parser & builder
├── plist.py          # Dependency-free Binary Plist (bplist00) parser & builder
├── dex.py            # Android classes.dex string table extractor
├── native.py         # ELF (.so) and Mach-O binary security inspection
├── scanner.py        # High-performance regex text/string scanner
├── rules.py          # Detection rule definitions (OWASP 2023 & 2016)
├── taxonomy.py       # CWE and MASVS v2 ids per rule
├── policy.py         # Config-file suppressions and baseline matching
├── models.py         # Core data models (Rule, Finding, PositiveCheck)
├── report.py         # Compliance scoring and JSON/MD/HTML/SARIF generators
├── archive.py        # Zip/tree readers with size limits
├── coverage.py       # Tracks files that were skipped or only partly analysed
├── samples.py        # Pure-Python vulnerable APK/IPA fixtures for `masa demo`
└── decompile.py      # Optional external decompiler wrapper (jadx/apktool)
```

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest --cov=masa
```

The tests use `unittest` cases and also run under `pytest`. The suite builds
its own vulnerable APK/IPA fixtures, so no Android SDK or Xcode is required.
`tests/test_detection.py` pairs every rule with a vulnerable and a safe
sample, and scans a clean Android project and iOS bundle to catch false
positives.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

Distributed under the [MIT License](LICENSE).

## Author

Built by **Guerfi Ahmed Yacine**, a cyber security engineering student at ESI Sidi Bel Abbès. Portfolio: [n4khla.github.io](https://n4khla.github.io) · [LinkedIn](https://www.linkedin.com/in/guerfi-ahmed-yacine-6831b32b8/)
