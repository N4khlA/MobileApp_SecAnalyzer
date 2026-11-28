# masa vs MobSF

Both tools scanned the same 32 pinned apps (`corpus.json`) on 2026-11-28/29:
masa 1.4.1 without a decompiler, and MobSF v4.6.9 (Docker image
`opensecurity/mobile-security-framework-mobsf:latest`, default settings),
which decompiles every app with jadx. Raw MobSF reports come from
`bench/mobsf.py`; they are not committed.

| | masa 1.4.1 | MobSF 4.6.9 |
|---|---|---|
| Recall on the 14 verified weaknesses | **8/14 (57%)** | **4/14 (29%)** |
| Precision on the 27 clean apps | **82%** (805/977, every finding labelled) | **70%** (28/40, random sample, ±14 pts) |
| Total scan time, 32 apps | **500 s** | **5,076 s** |
| Install size | 84 KB wheel, no dependencies | 0.7 GB compressed Docker image |
| Issues reported on the 27 clean apps | 1,012 findings (710 medium or higher) | 743 high/warning items |

The issue counts use different units: masa reports each piece of evidence,
MobSF one item per rule per app (with the files listed inside).

## Recall

The 14 weaknesses are InsecureBankv2's 13 published ones and UnCrackable
L1's ECB mode, each verified against MobSF's decompiled code
(`truth/*.json`, `_note`).

| Weakness | masa | MobSF (default) |
|---|---|---|
| Exported components | yes (CFG-001) | yes (`explicitly_exported`) |
| `allowBackup` | yes (CFG-002) | yes (`app_allowbackup`) |
| `debuggable` | yes (CFG-004) | yes (`app_is_debuggable`) |
| AES in ECB mode (UnCrackable L1) | yes (CRY-005) | yes (`android_aws_ecb_default`) |
| Cleartext HTTP | yes (NET-001) | no |
| External storage | yes (STO-003) | no |
| No obfuscation | yes (BIN-002) | no rule for it |
| Old target SDK | yes (SCP-001) | no (`vulnerable_os_version` is about minSdk) |
| Credentials in logs | no | no |
| Credentials in SharedPreferences | no | no |
| Plaintext SQLite | no | no |
| WebView JavaScript | no | no |
| Hardcoded IV | no | no |
| Key from a hardcoded string | no | no |

**MobSF reports nothing from InsecureBankv2's code.** Its jadx
decompilation succeeds (the classes can be read back through its
`view_source` API), but code analysis and URL extraction return 0 findings
and 0 URLs for this app, while they work on the other 31. An obvious
suspect is `SKIP_CLASS_PATH` in `mobsf/MobSF/settings.py`, which lists
`com/android/` (InsecureBankv2's package is `com.android.insecurebankv2`).
Removing that entry inside the container and rescanning changed nothing (0
findings again), so the cause is still unexplained. The 13 InsecureBankv2
weaknesses therefore measure MobSF's result on this app, not its rules; on
an app it does analyse, such as UnCrackable L1, it found the expected
weakness.

masa's six misses are code-level: dex strings alone cannot show that a
password reaches `Log.d` or that an IV array is all zeros.

## Precision

A random sample of 40 of MobSF's 743 high/warning items on the clean apps
(seed 2026), judged with the same criterion as masa's labels (is the claim
true for its evidence?, `LABELLING.md`). True: exported components, backup,
cleartext, Janus (v1 signing with minSdk 23), SHA-1 and weak-cipher use,
`java.util.Random`, task affinity, user-CA trust, a SHA-1 signing
certificate. False (12):

- "Files may contain hardcoded sensitive information" (3/3): `password` and
  `username` fields and UI-state classes, no literal values.
- "This app may contain hardcoded secrets" (2/2): translated UI strings that
  contain "password" or "auth".
- "IP Address disclosure" (2/2): a `192.168.1.1` input placeholder and a
  `127.0.0.1` OAuth redirect.
- "Protected by a permission, but the protection level should be checked"
  (4/4): `DUMP`, `BIND_QUICK_SETTINGS_TILE` and `BIND_CHOOSER_TARGET_SERVICE`,
  all system/signature permissions.
- A content provider reported "not Protected" although it declares
  `readPermission` and `writePermission`.

## Where each tool is ahead

- masa reads strings in Flutter's compiled Dart code (`libapp.so`): it found
  Obtainium's store APIs (APKPure, RuStore, IzzyOnDroid, Aptoide), which are
  not in MobSF's URL list.
- MobSF's permission list for InsecureBankv2 omits three declared
  permissions (`READ_PHONE_STATE`, `READ_CALL_LOG`, `READ_EXTERNAL_STORAGE`
  with `maxSdkVersion="18"`); masa lists all twelve.
- The two tools agree library by library on missing stack canaries
  (e.g. `libsqliteJni.so` on arm64/x86_64 only).
- MobSF sees code: on the apps it analyses it reports code-level issues
  (weak hashes and ciphers with their files) that a string scan only infers.

## Reproducing

    openssl rand -hex 32 > ~/.mobsf_key && chmod 600 ~/.mobsf_key
    sudo docker run -d --name mobsf -p 127.0.0.1:8000:8000 \
        -e MOBSF_API_KEY="$(cat ~/.mobsf_key)" \
        opensecurity/mobile-security-framework-mobsf:latest
    python bench/mobsf.py          # ~85 min for the 32 apps

The no-skip check: remove `'com/android/', ` from `SKIP_CLASS_PATH` inside
the container, restart it, and run
`python bench/mobsf.py --suffix noskip InsecureBankv2` (it still returned 0
code findings).
