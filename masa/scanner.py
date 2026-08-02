"""Regex-based source/binary scanner over the rule set."""

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import Finding, Rule, mask_secret

_TEXT_EXTS: Set[str] = {
    "java", "kt", "kts", "smali", "swift", "m", "mm", "h", "cpp", "cc", "c",
    "js", "ts", "json", "xml", "yml", "yaml", "properties", "gradle", "plist",
    "config", "cfg", "ini", "txt", "md", "html", "htm", "css", "sh", "py",
    "rb", "php", "proto", "toml",
}


class CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.re = re.compile(rule.pattern, re.MULTILINE) if rule.pattern else None


class Scanner:
    """Scans text files line-by-line and binary blobs for rule matches."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.compiled: Dict[str, CompiledRule] = {r.id: CompiledRule(r) for r in rules}

    # ---- text (line-oriented, with snippet context) ----

    def scan_text(self, content: str, filename: str, findings: List[Finding]) -> List[Finding]:
        """content: str, filename: display path. Appends Findings."""
        lines = content.split("\n")
        for rid, cr in self.compiled.items():
            if not cr.re:
                continue
            for m in cr.re.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                line = lines[line_no - 1] if line_no <= len(lines) else ""
                match = m.group(0)
                snippet = line.strip()[:240] if line else ""
                findings.append(Finding(
                    cr.rule, file=filename, line=line_no, snippet=snippet,
                    match=mask_secret(match),
                    extra={"context": self._context(lines, line_no)}))
        return findings

    @staticmethod
    def _context(lines: List[str], line_no: int, radius: int = 1) -> str:
        start = max(0, line_no - 1 - radius)
        end = min(len(lines), line_no + radius)
        return "\n".join("%4d | %s" % (i + 1, lines[i].strip()[:160])
                         for i in range(start, end))

    # ---- binary blobs (dex, .so, Mach-O): scan extracted strings ----

    def scan_strings(self, strings: List[str], filename: str, findings: List[Finding],
                     offset_base: int = 0) -> List[Finding]:
        """Scan a list of extracted strings; findings are binary evidence."""
        for i, s in enumerate(strings):
            for rid, cr in self.compiled.items():
                if not cr.re:
                    continue
                m = cr.re.search(s)
                if m:
                    findings.append(Finding(
                        cr.rule, file=filename, line=offset_base + i,
                        snippet=s, match=mask_secret(m.group(0)),
                        evidence_type="binary"))
        return findings

    def scan_all(self, files: List[Tuple[str, str]], findings: Optional[List[Finding]] = None) -> List[Finding]:
        """files: list of (display_name, text_content). Returns findings."""
        if findings is None:
            findings = []
        for name, content in files:
            self.scan_text(content, name, findings)
        return findings


def is_text_ext(name: str) -> bool:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in _TEXT_EXTS


def decode_text(raw: bytes) -> str:
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return raw.decode("utf-8", "replace")

