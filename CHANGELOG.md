# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [Unreleased]

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
