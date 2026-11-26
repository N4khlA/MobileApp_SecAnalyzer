"""CWE and OWASP MASVS v2 ids for every rule.

Auditors and code-scanning dashboards group findings by these ids. Where no
CWE describes the weakness well (missing obfuscation, missing root
detection), the CWE is left empty rather than forced.

MASVS v2 controls: https://mas.owasp.org/MASVS/
"""

from typing import Dict, Optional, Tuple

# rule id -> (CWE, MASVS control)
TAXA: Dict[str, Tuple[Optional[str], Optional[str]]] = {
    # secrets / credentials
    "SEC-001": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-002": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-003": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-004": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-005": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-006": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-007": ("CWE-321", "MASVS-CRYPTO-2"),
    "SEC-008": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-009": ("CWE-259", "MASVS-STORAGE-1"),
    "SEC-010": ("CWE-798", "MASVS-STORAGE-1"),
    "SEC-011": ("CWE-200", "MASVS-STORAGE-1"),
    # cryptography
    "CRY-001": ("CWE-327", "MASVS-CRYPTO-1"),
    "CRY-002": ("CWE-328", "MASVS-CRYPTO-1"),
    "CRY-003": ("CWE-328", "MASVS-CRYPTO-1"),
    "CRY-004": ("CWE-327", "MASVS-CRYPTO-1"),
    "CRY-005": ("CWE-327", "MASVS-CRYPTO-1"),
    "CRY-006": ("CWE-1204", "MASVS-CRYPTO-1"),
    "CRY-007": ("CWE-760", "MASVS-CRYPTO-1"),
    "CRY-008": ("CWE-916", "MASVS-CRYPTO-2"),
    "CRY-009": ("CWE-327", "MASVS-CRYPTO-1"),
    "CRY-010": ("CWE-335", "MASVS-CRYPTO-1"),
    "CRY-011": ("CWE-780", "MASVS-CRYPTO-1"),
    "CRY-012": ("CWE-327", "MASVS-CRYPTO-1"),
    # data storage
    "STO-001": ("CWE-312", "MASVS-STORAGE-1"),
    "STO-002": ("CWE-732", "MASVS-STORAGE-1"),
    "STO-003": ("CWE-922", "MASVS-STORAGE-1"),
    "STO-004": ("CWE-311", "MASVS-STORAGE-1"),
    "STO-005": ("CWE-276", "MASVS-STORAGE-1"),
    "STO-006": ("CWE-312", "MASVS-STORAGE-1"),
    "STO-007": ("CWE-312", "MASVS-STORAGE-1"),
    "STO-008": ("CWE-922", "MASVS-STORAGE-1"),
    "STO-009": ("CWE-311", "MASVS-STORAGE-1"),
    # network
    "NET-001": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-002": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-003": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-004": ("CWE-295", "MASVS-NETWORK-1"),
    "NET-005": ("CWE-297", "MASVS-NETWORK-1"),
    "NET-006": ("CWE-295", "MASVS-NETWORK-2"),
    "NET-007": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-008": ("CWE-1051", "MASVS-NETWORK-1"),
    "NET-009": ("CWE-598", "MASVS-NETWORK-1"),
    "NET-010": ("CWE-1051", "MASVS-NETWORK-1"),
    "NET-011": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-012": ("CWE-668", "MASVS-PLATFORM-2"),
    "NET-013": ("CWE-668", "MASVS-PLATFORM-2"),
    "NET-014": ("CWE-749", "MASVS-PLATFORM-2"),
    "NET-016": ("CWE-319", "MASVS-NETWORK-1"),
    "NET-017": ("CWE-295", "MASVS-NETWORK-1"),
    "NET-018": ("CWE-79", "MASVS-PLATFORM-2"),
    # logging
    "LOG-001": ("CWE-532", "MASVS-STORAGE-2"),
    "LOG-002": ("CWE-532", "MASVS-STORAGE-2"),
    # authentication / authorization
    "ATH-001": ("CWE-312", "MASVS-STORAGE-1"),
    "ATH-002": ("CWE-602", "MASVS-AUTH-1"),
    "ATH-003": ("CWE-287", "MASVS-AUTH-2"),
    "ATH-004": ("CWE-939", "MASVS-PLATFORM-1"),
    # input validation
    "INP-001": ("CWE-89", "MASVS-CODE-4"),
    "INP-002": ("CWE-22", "MASVS-CODE-4"),
    "INP-003": ("CWE-749", "MASVS-PLATFORM-2"),
    # privacy
    "PRI-001": ("CWE-359", "MASVS-PRIVACY-2"),
    "PRI-002": ("CWE-359", "MASVS-PRIVACY-3"),
    "PRI-003": ("CWE-359", "MASVS-PRIVACY-3"),
    "PRI-004": ("CWE-200", "MASVS-PLATFORM-3"),
    "PRI-005": ("CWE-200", "MASVS-PLATFORM-3"),
    # configuration
    "CFG-001": ("CWE-926", "MASVS-PLATFORM-1"),
    "CFG-002": ("CWE-530", "MASVS-STORAGE-2"),
    "CFG-003": ("CWE-530", "MASVS-STORAGE-2"),
    "CFG-004": ("CWE-489", "MASVS-RESILIENCE-4"),
    "CFG-005": ("CWE-1051", None),
    "CFG-006": ("CWE-926", "MASVS-PLATFORM-1"),
    "CFG-007": ("CWE-732", "MASVS-PLATFORM-1"),
    "CFG-008": ("CWE-477", "MASVS-PLATFORM-1"),
    "CFG-009": ("CWE-668", "MASVS-PLATFORM-1"),
    # permissions
    "PERM-001": ("CWE-250", "MASVS-PRIVACY-1"),
    "PERM-002": ("CWE-250", "MASVS-PRIVACY-1"),
    "PERM-003": ("CWE-250", "MASVS-PRIVACY-1"),
    "PERM-004": ("CWE-250", "MASVS-PRIVACY-1"),
    # binary protections
    "BIN-002": (None, "MASVS-RESILIENCE-3"),
    "BIN-003": (None, "MASVS-RESILIENCE-1"),
    "BIN-004": (None, "MASVS-RESILIENCE-3"),
    "BIN-005": ("CWE-347", "MASVS-RESILIENCE-2"),
    "BIN-006": ("CWE-347", "MASVS-RESILIENCE-2"),
    # IPC
    "IPC-001": ("CWE-610", "MASVS-PLATFORM-1"),
    "IPC-002": ("CWE-927", "MASVS-PLATFORM-1"),
    "IPC-003": ("CWE-927", "MASVS-PLATFORM-1"),
    "IPC-004": ("CWE-940", "MASVS-PLATFORM-1"),
    "IPC-005": ("CWE-940", "MASVS-PLATFORM-1"),
    "IPC-006": ("CWE-925", "MASVS-PLATFORM-1"),
    # supply chain
    "SCP-001": ("CWE-1104", "MASVS-CODE-1"),
    "SCP-002": ("CWE-1104", "MASVS-CODE-3"),
    "SCP-003": ("CWE-94", "MASVS-CODE-4"),
    "SCP-004": ("CWE-1104", "MASVS-CODE-1"),
    # native code
    "NAT-001": ("CWE-120", "MASVS-CODE-4"),
    "NAT-002": ("CWE-327", "MASVS-CRYPTO-1"),
    "NAT-003": ("CWE-78", "MASVS-CODE-4"),
    "NAT-004": ("CWE-338", "MASVS-CRYPTO-1"),
    "NAT-006": ("CWE-693", "MASVS-CODE-4"),
    "NAT-007": ("CWE-693", "MASVS-CODE-4"),
    "NAT-008": ("CWE-693", "MASVS-CODE-4"),
    "NAT-009": ("CWE-693", "MASVS-CODE-4"),
    "NAT-010": ("CWE-693", "MASVS-CODE-4"),
}

