# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

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
