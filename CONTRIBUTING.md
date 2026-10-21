# Contributing

Keep it small and standard-library only. The runtime package must not gain
third-party dependencies.

## Setup

```bash
git clone https://github.com/N4khlA/MobileApp_SecAnalyzer.git
cd MobileApp_SecAnalyzer
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .
pytest --cov=masa
```

## Adding a rule

1. Add the `Rule(...)` entry to the relevant list in `masa/rules.py` and include
   the OWASP 2023 category plus a remediation.
2. Add a fixture or a scanner test that proves the rule fires and, where it
   matters, that it does not fire on the safe pattern.
3. Keep detection conservative. A noisy rule is worse than a missing one.

Bug reports with a sample file are more useful than a description alone. Do not
attach apps you are not allowed to share.
