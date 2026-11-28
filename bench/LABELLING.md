# How the findings were labelled

First pass by Claude (2026-11-28), to be reviewed. Labels live in
`truth/<app>.json` under `labels`, keyed by finding fingerprint.

**tp** means the rule's claim is true for that evidence: the URL really is an
endpoint, the component really is exported without a permission. It does
not mean "exploitable". **fp** means the evidence does not show what the rule
says. When the evidence cannot settle it, the finding stays unlabelled
rather than guessed.

| Rule | tp when | fp when |
|---|---|---|
| NET-010 | a backend, OAuth or tile-server URL the app calls | OAuth scope IDs (`googleapis.com/auth/…`), doc links in bundled `.md` |
| NET-001 | the app plausibly fetches it over http (tile server, mail autoconfig) | namespaces, DTDs, scheme IDs, license/homepage links, library metadata |
| CFG-001, CFG-002, CFG-006, CFG-007, NET-002, PERM-001, PERM-004, SCP-001, SCP-004, BIN-004, BIN-005 | the manifest/binary says so (spot-checked against the raw XML) | — |
| CFG-005 | a staging/dev host the app contacts (`staging.tasks.org`, `auth-stage.tb.pro`) | dev hosts inside a URL-pattern list (FairEmail `debounce.json`) |
| PRI-001 | the app declares `READ_PHONE_STATE`, without which `getDeviceId` fails | no such permission (compat-library reference only) |
| STO-003 | the app stores downloads/exports/attachments on external storage | UnCrackable apps (library reference only) |
| BIN-002 | the app's own classes keep their names (InsecureBankv2, UnCrackable L3) | UnCrackable L1/L2, renamed by R8 |
| BIN-003 | the app lacks root detection | UnCrackable apps, which have it |
| CRY-001, CRY-004, CRY-005, CRY-011 | an exact transformation string (`AES/ECB/PKCS5Padding`, `RC4`) | catalog entries (`Alg.Alias.*`), error messages, the JDK disabled list, a regex that *blocks* RC4 |
| IPC-004 | — | bare `checkCallingOrSelf…Permission` references, no IPC gate in sight |
| PERM-003 | the permission combination exists | Tasks' "location tracking without need": it needs location for reminders |
| PERM-002 | — | WRITE_EXTERNAL_STORAGE that the app does use |
| NAT-009 | `libsqliteJni.so`: full of stack buffers, so no canary import means no canaries | — |
| INP-002, NET-006, NET-008 | — | an error message; an ExoPlayer codec option; loopback `127.0.0.1` |
| SCP-002, SCP-003, STO-004, PRI-002, SEC-002, CRY-003 | the library/API/key is really there | — |

Left unlabelled (20): PRI-005 (FLAG_SECURE is an inlined int, so its absence
from strings proves nothing), NAT-009 on `libdatastore_shared_counter.so` (too
small to know whether any function needed a canary), PERM-002 for
InsecureBankv2's contacts and storage read (use not verifiable without
decompiling), BIN-002 on the UnCrackable iOS app.

Corrections after the first pass: UnCrackable L3's BIN-002 is tp (its Java
classes are not renamed; its protection is native), and the exact `RC4`/`rc4`
strings are tp, as the CRY criterion says.

Known bias: findings of a rule listed in an app's `expected` count as tp
without a label (see `run.py`), which flatters NET-001 on InsecureBankv2.
