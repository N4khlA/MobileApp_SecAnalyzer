"""Core data models shared across the analyzer."""

import hashlib
from typing import Any, Dict, List, Optional


SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
}

SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]

# OWASP Mobile Top 10 (2023 revision) - current framework
OWASP_2023: Dict[str, str] = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Protections",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

# OWASP Mobile Top 10 (2016) - legacy framework, kept for compatibility
OWASP_2016: Dict[str, str] = {
    "M1": "Insecure Data Storage",
    "M2": "Insecure Communication",
    "M3": "Insecure Authentication",
    "M4": "Insufficient Cryptography",
    "M5": "Insecure Authorization",
    "M6": "Inadequate Privacy",
    "M7": "Client Code Quality",
    "M8": "Code Tampering",
    "M9": "Reverse Engineering",
    "M10": "Extraneous Functionality",
}

LEGACY_MAP: Dict[str, Optional[str]] = {
    "M1": "M3",   # credential usage -> insecure authentication
    "M2": None,   # supply chain has no direct legacy equivalent
    "M3": "M5",   # auth/authz -> insecure authorization
    "M4": "M7",   # input/output validation -> client code quality
    "M5": "M2",   # communication -> insecure communication
    "M6": "M6",   # privacy
    "M7": "M9",   # binary protections -> reverse engineering
    "M8": "M10",  # misconfiguration -> extraneous functionality
    "M9": "M1",   # storage -> insecure data storage
    "M10": "M4",  # cryptography -> insufficient cryptography
}

CATEGORY_NAMES: Dict[str, str] = {
    "secrets": "Hardcoded secrets / credentials",
    "crypto": "Cryptographic implementation",
    "storage": "Data storage",
    "network": "Network communication",
    "logging": "Logging / privacy",
    "auth": "Authentication / authorization",
    "input": "Input/output validation",
    "privacy": "Privacy protections",
    "config": "Configuration",
    "binary": "Binary protections",
    "supplychain": "Supply chain",
    "native": "Native code",
    "permissions": "Android permissions",
}

RANK_NAMES: Dict[int, str] = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}


def rank_of(severity: str) -> str:
    try:
        idx = SEVERITY_ORDER.index(severity)
        return RANK_NAMES.get(idx + 1, "info")
    except ValueError:
        return "info"


class Rule:
    """A single detection rule (regex over text, or a programmatic check)."""

    def __init__(self, rule_id: str, title: str, severity: str, owasp: str, category: str,
                 pattern: Optional[str] = None, description: str = "", remediation: str = "", note: str = "") -> None:
        self.id = rule_id
        self.title = title
        self.severity = severity
        self.owasp = owasp            # 2023 category id, e.g. "M5"
        self.legacy = LEGACY_MAP.get(owasp, owasp)
        self.category = category
        self.pattern = pattern        # compiled lazily via scanner
        self.description = description
        self.remediation = remediation
        self.note = note

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "owasp": self.owasp,
            "owasp_name": OWASP_2023.get(self.owasp, ""),
            "legacy_owasp": self.legacy,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
        }


class Finding:
    """A concrete finding produced during analysis."""

    def __init__(self, rule: Rule, file: Optional[str] = None, line: Optional[int] = None,
                 snippet: str = "", match: str = "", evidence_type: str = "code",
                 extra: Optional[Dict[str, Any]] = None) -> None:
        self.rule = rule
        self.file = file
        self.line = line
        self.snippet = snippet
        self.match = match
        self.evidence_type = evidence_type   # code | manifest | binary | config | behavior
        self.extra = extra or {}

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def owasp(self) -> str:
        return self.rule.owasp

    def to_dict(self) -> Dict[str, Any]:
        d = self.rule.to_dict()
        d.update({
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "match": self.match,
            "evidence_type": self.evidence_type,
        })
        d.update(self.extra)
        return d


class PositiveCheck:
    """Positive security evidence (a control that was found in place)."""

    def __init__(self, key: str, description: str, evidence: str) -> None:
        self.key = key
        self.description = description
        self.evidence = evidence

    def to_dict(self) -> Dict[str, str]:
        return {"key": self.key, "description": self.description,
                "evidence": self.evidence}


def mask_secret(value: Optional[str], keep: int = 5) -> str:
    """Partially mask a matched secret for safe display."""
    if value is None:
        return ""
    value = value.strip()
    if len(value) <= 12:
        return value[:1] + "*" * (len(value) - 1)
    return value[:keep] + "*" * (len(value) - keep - keep) + value[-keep:]


def stable_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]

