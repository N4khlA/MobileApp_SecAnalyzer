# masa roadmap

Where masa is today (v1.4.0, on PyPI as `masa-scan`): 100 regex rules plus
programmatic manifest, plist and binary checks, each tagged with CWE and MASVS
ids. It is zero-dependency, reports in SARIF, JSON, Markdown and HTML, has a
coverage-honest "incomplete scan" signal, supports suppressions and baselines,
ships as a GitHub Action and passes 146 tests. On a labelled benchmark of
12 real apps its findings are 88% precise, with 57% recall of known weaknesses.

What holds it back: rules are hardcoded in Python, string-only scanning cannot
see code context (the recall ceiling), and apps built with Flutter, React Native or Xamarin go
almost unanalysed.

The direction is to become **the lightweight, CI-native MobSF alternative**: one
`pip install`, no server, honest about what it did not scan, with numbers
measured on real apps behind every rule.

---

## v1.3: usable in a real pipeline (released 2026-11-26)

The goal of v1.3 is that a team can adopt masa without it nagging them forever.

- [x] **Suppressions**: support an inline `// masa-ignore: SEC-006 reason` comment
      and a `.masa.toml` file with `ignore = [{rule, path, reason}]`. Suppressed
      findings still appear in JSON/SARIF with `suppressions[]` (SARIF supports
      this natively).
- [x] **Baseline mode**: `masa analyze app.apk --baseline old.json` reports only
      new findings. Fingerprint each finding as rule + file + normalised snippet,
      not by line number.
- [x] **CWE + MASVS/MASTG ids on every rule**, for example `SEC-001 → CWE-798,
      MASVS-STORAGE-1`. Put them in SARIF `taxa` and show them in the HTML report.
      Auditors look for these ids.
- [x] **Per-rule file scoping**: add `Rule.applies_to` (for example
      `{"java","kt","smali"}`) so crypto rules stop matching `.md` and `.json`.
      This is the cheapest false-positive win and it also speeds up scanning.
- [x] **PyPI release + GitHub Action**: `pip install masa-scan` (`masa` was
      taken) and `uses: N4khlA/MobileApp_SecAnalyzer@v1.3.0`, from this repo's
      `action.yml`. Releases publish through PyPI trusted publishing on a tag.

## v1.4: prove it works (1.4.0 released 2026-11-28; partly done)

The goal of v1.4 is a precision/recall table that no one can argue with.

- [~] **Benchmark corpus** in `bench/`, using known-vulnerable apps with published
      ground truth: OWASP MASTG test apps, DIVA, InsecureBankv2, AndroGoat,
      OVAA, and DVIA-v2 for iOS. Pin each by SHA-256 and fetch them with a
      script; don't commit the APKs. *Done for InsecureBankv2 and the four
      OWASP UnCrackable apps; DIVA, AndroGoat, OVAA and DVIA-v2 had no
      reachable download. Ground truth is a draft from published lists.*
- [~] **Clean corpus**: 50 to 100 popular open-source apps from F-Droid. Use it to
      measure the false-positive rate per rule. *7 apps so far, every
      finding labelled (`bench/LABELLING.md`).*
- [~] Add a `bench/run.py` script that writes per-rule TP/FP/FN, then a
      `BENCHMARK.md` table and a CI job that fails when precision regresses.
      *Script, table and `--check` done; the CI job is not wired up yet.*
- [ ] **Head-to-head comparison** with MobSF and semgrep's mobile rules on the same
      corpus, covering precision, recall, scan time and install size. This is
      the README headline and a paper section.
- [x] Demote or delete any rule below roughly 50% precision on the clean corpus,
      and log it in the CHANGELOG the way the existing "confesses everything"
      entries do. *Nine rules fixed (66% -> 88% overall); NET-001 demoted
      to medium at 33%.*

## v2.0: past regex (≈1–2 months)

The goal of v2.0 is to understand code, not just strings.

- [ ] **Rules as data**: move them to YAML (`rules/*.yml`) with `pattern`,
      `pattern-not` and `pattern-inside` fields, and fixtures next to each rule.
      Outsiders can then contribute rules without touching Python.
- [ ] **Light intra-procedural taint** on decompiled Java/Kotlin and smali, with
      sources (`getIntent().getExtras()`, `getStringExtra`, deep-link `Uri`) and
      sinks (`startActivity`, `rawQuery`, `loadUrl`, `File(...)`). Start with
      smali, because the register-based form is easier to track than Java text.
      This turns IPC-001 and the SQL injection and WebView rules from
      "API used" into "attacker data reaches the API".
- [ ] **Reachability**: drop findings in code that no exported component, receiver
      or deep link can reach. This means building a small call graph from smali.
- [ ] Stay zero-dependency in the core, and put the heavier analysis behind
      `pip install masa[deep]` if needed.

## v2.x: cross-platform frameworks (pick by demand)

Most store apps aren't plain Java or Swift any more. Each framework below is a
self-contained module.

- [ ] **React Native**: scan `assets/index.android.bundle` and `main.jsbundle`.
      Detect Hermes bytecode by its magic bytes and run string extraction on it.
      Add rules for `AsyncStorage` holding tokens and hardcoded `fetch` endpoints.
- [ ] **Flutter**: extract strings from `libapp.so` and check for `badCertificateCallback`
      returning true and `shared_preferences` holding secrets.
- [ ] **Xamarin/.NET MAUI**: strings from the `assemblies/*.dll` and `assemblies.blob`
      stores.
- [ ] **Cordova/Capacitor**: `www/` plus `config.xml` `<access origin="*">`.
- [ ] Report the detected framework in the coverage block, so the report says
      "Flutter app: Dart code scanned as strings only" instead of looking clean.

## Later / optional

- SBOM: list third-party SDKs (Firebase, Facebook, ad SDKs) found by package
  prefix, and match them against OSV for known-vulnerable versions. This covers
  OWASP M2 properly.
- Diff mode: `masa diff v1.apk v2.apk` lists permissions, exported components
  and endpoints added between releases.
- A small dynamic companion that generates a Frida script that hooks exactly the
  APIs the static findings point at.

---

## What "bigger and better" looks like

| Milestone | Proof point |
|---|---|
| v1.3 | Installable from PyPI, used in your own CI, plus one external repo using the Action |
| v1.4 | `BENCHMARK.md` with precision/recall against MobSF on public apps |
| v2.0 | Taint findings with source→sink traces, and a lower FP rate than v1.4 on the same corpus |
| Paper | "Lightweight static analysis of mobile apps: how far does a zero-dependency scanner get?" The v1.4 benchmark plus the v2.0 taint delta is enough for a workshop paper or a strong PFE report |

Suggested order: build v1.4 before v2.0. Without the benchmark you cannot show
that taint analysis improved anything.
