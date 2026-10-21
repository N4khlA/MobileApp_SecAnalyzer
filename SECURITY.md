# Security Policy

## Supported versions

The latest 1.x release receives security fixes.

## Reporting a vulnerability

Email **ay.guerfi@esi-sba.dz** with the affected version, a minimal
reproduction and the impact. Please do not open a public issue before a fix is
available. I aim to acknowledge reports within seven days.

## Scope

`masa` parses untrusted APK and IPA files and can invoke optional external
decompilers (`apktool`, `jadx`, `dex2jar`). Only run those tools on input you
are authorized to inspect, and keep them in a disposable container when the
file is hostile.

This is a static analyzer. Findings can be false positives or false negatives,
and a clean report does not prove that an application is secure.

## Out of scope

- Applications you do not own or have permission to test.
- Bugs in third-party decompilers.
- Missing detections without a concrete sample and rule proposal.
