# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [Unreleased]

### Added

- `bench/`: a benchmark on real apps. `python bench/run.py` downloads a
  pinned corpus (InsecureBankv2, OWASP UnCrackable, 7 F-Droid apps), scans
  it and scores recall and precision against `bench/truth/`, writing
  `bench/BENCHMARK.md`; `--check` fails when a rule scores worse.

### Changed

- NET-010 (hardcoded API endpoint) now needs an API-shaped URL: an `api`
  host (`api.x`, `api-v2.x`, `*apis.com`) or an `/api`, `/rest`, `/graphql`,
  `/rpc` or `/vN` path segment. It used to match any URL, and on the
  benchmark 98% of its 7,726 hits were licenses, docs, XML schemas and
  timezone data. It now fires 174 times, nearly all on real backends.
- NET-001 (cleartext HTTP URL) skips URLs that are never fetched: XML
  namespaces and schemas (`schemas.*`, `schema.org`, `purl.org`,
  `xmlpull.org`, `microformats.org`), JAXP property names
  (`http://javax.xml.…`) and license links (Apache, GNU, OSI). The bundled
  Public Suffix List (`public_suffix_list.dat`, `effective_tld_names.dat`)
  is no longer text-scanned: its comments name every domain registry's
  website. On the benchmark NET-001 went from 1,773 hits to 122.
- CRY-001 (DES/3DES) matches the transformation code asks for: `"DES"`,
  `"DESede"`, `"DES/CBC/PKCS5Padding"` and the like, quoted in source or as
  a whole dex string, plus `kCCAlgorithmDES`/`kCCAlgorithm3DES`. It no
  longer fires on TLS cipher-suite tables, OpenSSL and BouncyCastle
  algorithm catalogs, SQLite's `fts3DestroyMethod` (a case-insensitive
  `3DES` match), or bare `CCCrypt`, which CommonCrypto also uses for AES.
  Known gap: an app that explicitly enables a `3DES_EDE` TLS suite is no
  longer reported. On the benchmark CRY-001 went from 493 hits to 7.
- Weak-crypto rules (OWASP M10, e.g. NAT-002, CRY-004) skip bundled crypto
  libraries (`libconscrypt*`, `libcrypto*`, `libssl*`, `libsqlcipher*`, …):
  a TLS library exports `EVP_des_cbc` because it implements DES, not because
  the app uses it. Secret, endpoint and hardening checks still run on them.
  NAT-002 went from 477 hits to 0, all of them in Conscrypt.
- PRI-002 (analytics/tracking SDK) is case-sensitive and finds Adjust by its
  package (`com.adjust.sdk`, `ADJConfig` on iOS). `(?i)Adjust` matched the
  word "adjust" in every app (`setAdjustViewBounds`, SQLite's
  `whereRangeAdjust`, ...): 429 of its 431 benchmark hits, all in F-Droid
  apps, which ban trackers. It now also detects Google Analytics by its entry
  class. On the benchmark: 431 hits to 1, Google Analytics in InsecureBankv2.
- CFG-005 (staging/test endpoint) needs the keyword as a whole host label or
  a dash-separated part of one (`staging.x`, `api-dev.x`, `qa2.x`), never the
  TLD, or a special-use `.test`/`.internal`/`.local` host. "dev" inside
  `developer.android.com`/`developers.google.com` and the public `.dev` TLD
  (`protobuf.dev`, `amp.dev`) were 96% of its hits. Also added `stage`,
  `stg`, `uat` and `preprod`. On the benchmark: 268 hits to 12.
- Every rule under 50% precision on the labelled benchmark was fixed
  (`bench/LABELLING.md` has the criteria); overall precision went from 66%
  to 88%, recall unchanged:
  - NET-008 skips loopback (`127.*`, `0.0.0.0`).
  - NET-006: `allowInsecure` must be a whole word, not part of ExoPlayer's
    `forceAllowInsecureDecoderComponents`.
  - INP-* run on source code only: `new File(` never survives compilation,
    so in dex it only ever matched messages.
  - IPC-004 needs a call (`checkCallingOrSelfPermission(`); bare method names
    in dex are references from AndroidX.
  - CRY-004 matches the transformation (`"RC4"`, `"ARCFOUR"`,
    `kCCAlgorithmRC4`), not catalogs or cipher blocklists.
  - PRI-001 drops telephony IDs (`getDeviceId`, `getImei`, ...) when the app
    lacks `READ_PHONE_STATE`, without which the call only throws (8% -> 100%).
  - CFG-005 skips URL patterns with `*` wildcards (link-cleaning lists).
  - BIN-002 counts R8/ProGuard's 1-2 letter class names as obfuscation
    evidence; compiled apps rarely contain the word "ProGuard".
  - NET-001 (15% -> 33%) skips docs (extensionless `README`, `CHANGES`,
    `LICENSE`, ... are docs now), comment-only lines (also NET-010), "See /
    Check http://..." messages, DTD identifiers, `/ns/` namespaces, media and
    XML-feature identifiers, `example.com`, MPL/EPL license links, and the
    generated `aboutlibraries.json` credits list. Its remaining false
    positives are library homepage strings that a string cannot tell apart
    from a real URL.
- NET-001 is now **medium** (was high). At 33% precision on the benchmark, an
  `http://` string alone cannot show the app fetches it, so it should not
  fail a `--fail-on high` build by itself. Cleartext enabled in the manifest
  or network security config (NET-002, NET-003) stays high.

## [1.3.1] - 2026-11-28

### Fixed

Found by the first benchmark run; none showed up on masa's own fixtures,
because the fixture builders shared each bug.

- Binary `AndroidManifest.xml` from real APKs was never read: string pool
  offsets were taken from the chunk start instead of `stringsStart`, and the
  AXML builder wrote them the same wrong way. Every real APK came out with
  no package, components or permissions, so all manifest checks (exported
  components, debuggable, backup, target SDK, permissions) were silent, while
  the scan still reported complete coverage. On InsecureBankv2, recall of
  the expected weaknesses went from 29% to 57%.
- The manifest `package` was looked up in the `android:` namespace and was
  always empty on real APKs.
- Any real IPA crashed masa: the provisioning-profile parser caught
  `plistlib.InvalidPlistException`, which does not exist. Real profiles are
  CMS-signed, so they always hit that path. The embedded plist is now
  parsed, which also makes the `get-task-allow` check (CFG-004) work on real
  IPAs.
- `META-INF/*.SF` and `*.MF` signature files were scanned as code, so their
  `SHA1-Digest` lines fired NAT-002 about 1,900 times across 12 apps.

## [1.3.0] - 2026-11-26

On PyPI under the name `masa-scan` (`masa` was taken). The command and the
import name stay `masa`.

### Added

- Suppressions: inline `masa-ignore` / `masa-ignore: ID[, ID] -- reason`
  comments, on the finding's line or on a comment line just above it, and a
  `.masa.toml` / `.masa.json` config with `[[ignore]]` entries (`rule`,
  `path` glob, required `reason`). Suppressed findings move
  to `suppressed` in JSON and carry SARIF `suppressions`; they no longer
  fail the gate or count toward the grade. `--config PATH` picks the file.
- Baseline mode: `--baseline old.report.json` keeps findings already in an
  earlier report as `baselined` (SARIF `baselineState: unchanged`), and only
  new ones fail the gate. Baselines must come from masa 1.3 or later.
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
