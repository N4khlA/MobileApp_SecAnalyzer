# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [Unreleased]

Ships as 1.3.0 on PyPI under the name `masa-scan` (`masa` was taken). The
command and the import name stay `masa`.

### Added

- Suppressions: inline `masa-ignore` / `masa-ignore: ID[, ID] -- reason`
  comments, on the finding's line or on a comment line just above it, and a
  `.masa.toml` / `.masa.json` config with `[[ignore]]` entries (`rule`,
  `path` glob or `dir/` prefix, required `reason`). Suppressed findings move
  to `suppressed` in JSON and carry SARIF `suppressions`; they no longer
  fail the gate or count toward the grade. `--config PATH`, `--no-config`.
- Baseline mode: `--baseline old.report.json` keeps findings already in an
  earlier report as `baselined` (SARIF `baselineState: unchanged`), and only
  new ones fail the gate. Reports from 1.2 work as baselines.
- Every finding has a `fingerprint` (rule, file, normalised snippet, extra
  fields; no line number), so it survives code moving around.
- CWE and OWASP MASVS v2 ids on every rule (`masa/taxonomy.py`), in JSON,
  Markdown and HTML, in `masa rules`, and as SARIF tags
  (`external/cwe/cwe-798`) for GitHub code scanning.
- GitHub Action (`action.yml`): `uses: N4khlA/MobileApp_SecAnalyzer@v1.3.0`.
  It uploads SARIF and then applies the gate, so alerts show even on a failed
  build.
- Release workflow publishing to PyPI through trusted publishing (no stored
  token).
- Android IPC rules (`ipc` category): intent redirection (IPC-001), mutable
  implicit PendingIntent (IPC-002), sticky broadcasts (IPC-003),
  `check/enforceCallingOrSelfPermission` (IPC-004), caller identity from
  Intent extras or `getCreatorPackage` (IPC-005), dynamic receivers without
  an export flag (IPC-006).
- Manifest checks: providers with only read or write permission (CFG-006),
  components guarded by a `normal`/`dangerous` custom permission (CFG-007),
  deprecated `signatureOrSystem` (CFG-008), root-wide
  `grant-uri-permission` (CFG-009). Custom `<permission>` declarations are
  now parsed from both binary and plain-text manifests.
- `network_security_config.xml` trusting user CAs outside
  `<debug-overrides>` (NET-017); `<pin-set>` counts as pinning evidence.
- WebView JavaScript enabled (NET-018), secrets on the clipboard (PRI-004),
  no `FLAG_SECURE` (PRI-005).
- Biometrics used as a yes/no gate without a Keystore/Keychain key, on
  Android and iOS (ATH-003); custom iOS URL schemes (ATH-004).
- iOS storage: `kSecAttrAccessibleAlways` (STO-008) and disabled file Data
  Protection (STO-009).
- Binary hardening: missing stack canary on ELF and Mach-O (NAT-009),
  Objective-C without ARC (NAT-010), v1-only APK signing / Janus (BIN-005),
  unsigned APK (BIN-006, info).
- dex2jar + CFR decompiler pipeline (CFR via a `cfr` wrapper or
  `MASA_CFR_JAR`). jadx is now tried first, since the rules target Java
  source and apktool only yields smali.
- `tests/test_detection.py`: vulnerable/safe pairs for every new rule plus
  clean-app false-positive scans.

### Changed

- Pattern rules only run on the file kinds they apply to. API-call rules
  (crypto, storage, logging, auth, input, IPC, supply chain) skip
  configuration and documentation files; native rules (NAT-001..004) run on
  native binaries and C/C++/Objective-C source only. Secrets and endpoints
  are still reported in every file.
- SARIF `partialFingerprints` moved from `masa/v1` (included the line) to
  `masa/v2` (the line-free fingerprint). GitHub will re-open existing alerts
  once after upgrading.

### Fixed

- NAT-002 (weak crypto in native code) fired on Java source and dex strings,
  duplicating the CRY rules, yet missed OpenSSL symbols such as `MD5_Init`
  and `DES_key_schedule` because `\b` treats `_` as a word character. On
  the demo APK: 6 misplaced hits gone, 2 real ones in `libvulnbank.so` found.
- `android:exported="false"` in a plain-text manifest was read as the
  string `"false"`, which is truthy, so private components were reported as
  exported (CFG-001, high).
- Manifest findings have no line number, so de-duplication kept only the
  first exported component and the first dangerous permission.
- Gradle projects (`app/src/main/AndroidManifest.xml`) failed with
  "AndroidManifest.xml not found".
- Exported activities, services and receivers without an intent-filter
  were never reported. The launcher activity is no longer reported unless
  it also accepts other actions.
- Providers protected by `readPermission`/`writePermission` were reported
  as unprotected.
- BIN-002 and BIN-003 ("no obfuscation", "no root detection") carried a
  regex that matched the evidence itself, so they fired on the exact line
  that proved the protection was there.
- NET-010 fired on the `xmlns:android` schema URL in every manifest, and
  NET-001 (high) on the Apple DTD URL in every XML plist.
- 64-bit Mach-O `cryptid` was read from the padding field, so encrypted
  App Store binaries were reported as unencrypted (BIN-004).
- The AXML builder could not write `TYPE_INT_HEX` attributes.

### Changed

- Minimum Python version is 3.10. Python 3.9 reached end-of-life in October
  2025, and current pytest and setuptools releases no longer install on it.
- CI tests Python 3.10-3.14 and builds the wheel on 3.14.
- CI uses `actions/checkout@v7` and `actions/setup-python@v7`.
- Dependabot only raises a version floor when a new release falls outside the
  allowed range, and groups updates into one PR per ecosystem.

## [1.2.0] - 2026-10-21

### Added

- Scan coverage tracking. Every file that could not be analysed, and every
  file scanned only as raw strings, is listed in the console, JSON, Markdown,
  HTML and SARIF output.
- `--strict` fails the gate when any input file could not be analysed.
- Unrecognised `.so` files are now scanned as raw strings instead of skipped.

### Changed

- **Breaking:** exit codes now match Semgrep and Bandit. `1` means the gate
  failed (it was `2`), and `2` means an error (it was `1`). The old scheme
  could not tell a failed gate from a mistyped command, because argparse
  also exits `2`.
- `masa` with no command prints help to stderr and exits `2`.
- The reason for a failed gate is printed to stderr.
- APK and IPA loading share one reader in `masa/archive.py`.

### Fixed

- A zip entry with a forged size or bad CRC was silently dropped, so the
  scan looked cleaner than it was. On the demo APK, forging the size of
  `classes.dex` hid 18 of 38 findings with no warning.
- A corrupt deflate stream, an encrypted entry or an unsupported compression
  method aborted the whole scan instead of skipping that entry.
- Text files over 8 MiB, and folder-mode files over the size limit, were
  skipped without being reported.
- A finding on `AndroidManifest.xml` was reported again for the normalized
  manifest view, inflating counts and the risk score.
- The SHA-256 in the HTML report header was unreadable.

## [1.1.0] - 2026-10-21

### Added

- SARIF 2.1.0 output through `--sarif PATH`, including rule metadata and
  `security-severity` properties for code scanning.
- `--fail-on` severity gate. `masa analyze` exits 2 when a finding at or above
  the requested level is present.
- `--version` and the `masa 1.1.0` output.
- GitHub Actions CI for Python 3.9-3.13, plus a wheel build/install job.
- Dependabot configuration for pip and GitHub Actions.
- Zip size limits before APK/IPA entries are decompressed into memory.
- Tests for SARIF, the severity gate, archive limits and platform detection.

### Changed

- The sample fixture builder moved to `masa/samples.py`, so `masa demo` works
  from an installed wheel instead of only from a source checkout.
- `masa demo` writes to `./masa-demo` by default.
- Minimum Python version is 3.9. Python 3.8 is end-of-life.
- The report version string now comes from `masa.__version__`.
- Development setup uses `pip install -e ".[dev]"`.

### Fixed

- `detect_platform` treated any path containing `.app` as an iOS bundle.
- Removed unused imports and variables reported by ruff.
