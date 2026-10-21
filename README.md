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
- **OWASP Mobile Top 10 Compliance**: Scores app posture across all 10 categories (M1-M10) with positive security control detection (Keystore, Keychain, AEAD ciphers, Biometrics, Pinning).
- **Optional Decompiler Integration**: Automatically uses `apktool`, `jadx`, `dex2jar`, or `cfr` if available on `PATH`.
- **Multi-Format Reporting**: Generates interactive HTML dashboards, Markdown summaries, structured JSON reports and SARIF 2.1.0 for code scanning.
- **CI Gate**: `--fail-on` turns findings into a non-zero exit code, so a pipeline can block on critical or high severity issues.

---

## Installation

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

# Analyze a unpacked directory (apktool output or source tree)
masa analyze path/to/AndroidProject/ -o output_dir/
```

### 3. List Detection Rules
```bash
# List all active security rules
masa rules

# Filter rules by category (secrets, crypto, storage, network, privacy, etc.)
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
| **M3** | Insecure Authentication/Authorization | Exposed component receivers without permissions, client-side authorization checks |
| **M4** | Insufficient Input/Output Validation | SQL injection (`rawQuery`), path traversal, dangerous WebView JavaScript bridges |
| **M5** | Insecure Communication | Cleartext HTTP URLs, ATS bypasses, `TrustAll` certificate manager overrides, hostname verification bypasses |
| **M6** | Inadequate Privacy Protections | PII/credential logging in logcat/NSLog, hardware ID harvesting (IMEI/MAC), ATT prompt checks |
| **M7** | Insufficient Binary Protections | Unsafe string functions in native code (`strcpy`, `sprintf`), non-PIE binaries, missing RELRO, executable stack |
| **M8** | Security Misconfiguration | Debuggable builds, backup enabled without rules (`allowBackup=true`), staging endpoints |
| **M9** | Insecure Data Storage | Plaintext SharedPreferences, `NSUserDefaults` token storage, world-readable/writable files |
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

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

Distributed under the [MIT License](LICENSE).

## Author

Built by **Guerfi Ahmed Yacine**, a cyber security engineering student at ESI Sidi Bel Abbès. Portfolio: [n4khla.github.io](https://n4khla.github.io) · [LinkedIn](https://www.linkedin.com/in/guerfi-ahmed-yacine-6831b32b8/)
