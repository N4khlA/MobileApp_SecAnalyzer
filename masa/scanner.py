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


_KINDS_BY_EXT: Dict[str, str] = {}
for _kind, _exts in {
    "source": ("java", "kt", "kts", "smali", "swift", "js", "jsx", "ts", "tsx",
               "dart", "py", "rb", "php", "sh"),
    "native_source": ("c", "cc", "cpp", "cxx", "h", "hpp", "m", "mm"),
    "config": ("json", "xml", "yml", "yaml", "properties", "gradle", "plist",
               "config", "cfg", "ini", "toml", "proto", "xcconfig"),
    "doc": ("md", "txt", "html", "htm", "css"),
}.items():
    for _ext in _exts:
        _KINDS_BY_EXT[_ext] = _kind


def file_kind(name: str) -> str:
    """Classify a text file by extension: source, native_source, config, doc
    or other. A suffix like "AndroidManifest.xml (normalized)" is ignored."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1].split(" (", 1)[0]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    return _KINDS_BY_EXT.get(ext, "other")


_IGNORE = re.compile(
    r"masa-ignore(?::?\s*((?:[A-Z]+-\d+)(?:\s*,\s*[A-Z]+-\d+)*))?"
    r"(?:\s*(?:--|:)\s*(.*?))?\s*(?:\*/|-->)?\s*$")


_COMMENT_STARTS = ("//", "#", "/*", "*", "<!--", ";", "--")


def inline_suppression(lines: List[str], line_no: int,
                       rule_id: str) -> Optional[str]:
    """Return the justification when the finding's line, or the line above
    it, carries ``masa-ignore`` (all rules) or ``masa-ignore: ID[, ID]``
    (those rules), optionally followed by ``-- reason``. None otherwise."""
    for idx in (line_no - 1, line_no - 2):
        if not 0 <= idx < len(lines):
            continue
        # the line above only counts when it is a comment on its own, so a
        # trailing ignore on one statement does not leak onto the next
        if idx == line_no - 2 and not lines[idx].lstrip().startswith(
                _COMMENT_STARTS):
            continue
        m = _IGNORE.search(lines[idx])
        if not m:
            continue
        ids = m.group(1)
        if ids and rule_id not in {i.strip() for i in ids.split(",")}:
            continue
        return (m.group(2) or "").strip() or "suppressed inline"
    return None


class CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.re = re.compile(rule.pattern, re.MULTILINE) if rule.pattern else None
        self.targets = rule.targets

    def applies_to(self, kind: str) -> bool:
        return self.targets is None or kind in self.targets


class Scanner:
    """Scans text files line-by-line and binary blobs for rule matches."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.compiled: Dict[str, CompiledRule] = {r.id: CompiledRule(r) for r in rules}

    # ---- text (line-oriented, with snippet context) ----

    def scan_text(self, content: str, filename: str, findings: List[Finding]) -> List[Finding]:
        """content: str, filename: display path. Appends Findings."""
        lines = content.split("\n")
        kind = file_kind(filename)
        has_ignore = "masa-ignore" in content
        for rid, cr in self.compiled.items():
            if not cr.re or not cr.applies_to(kind):
                continue
            for m in cr.re.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                line = lines[line_no - 1] if line_no <= len(lines) else ""
                match = m.group(0)
                snippet = line.strip()[:240] if line else ""
                finding = Finding(
                    cr.rule, file=filename, line=line_no, snippet=snippet,
                    match=mask_secret(match),
                    extra={"context": self._context(lines, line_no)})
                if has_ignore:
                    reason = inline_suppression(lines, line_no, rid)
                    if reason is not None:
                        finding.suppression = {"kind": "inSource",
                                               "justification": reason}
                findings.append(finding)
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
        kind = "dex" if filename.lower().endswith(".dex") else "native"
        active = [cr for cr in self.compiled.values()
                  if cr.re and cr.applies_to(kind)]
        for i, s in enumerate(strings):
            for cr in active:
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

