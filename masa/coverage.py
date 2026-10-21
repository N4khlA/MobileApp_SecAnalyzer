"""Track input that was not fully analysed.

A static scanner that silently drops a file reports fewer findings than the app
really has. Every file that is skipped, or scanned with a weaker fallback, is
recorded here so the report and the CLI can say the scan was incomplete.
"""

from typing import Any, Dict, List

UNREADABLE = "unreadable"
TOO_LARGE = "too_large"

# Formats that never carry scannable code or configuration.
MEDIA_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
              ".wav", ".mp3", ".ogg", ".m4a", ".mov", ".mp4",
              ".ttf", ".otf", ".woff", ".woff2")


def is_media(name: str) -> bool:
    return name.lower().endswith(MEDIA_EXTS)


def human_size(n: int) -> str:
    if n < 1024:
        return "%d bytes" % n
    size = n / 1024.0
    for unit in ("KiB", "MiB"):
        if size < 1024:
            return "%g %s" % (round(size, 1), unit)
        size /= 1024
    return "%g GiB" % round(size, 1)


class Coverage:
    """Files seen, files skipped and files scanned with a fallback."""

    def __init__(self) -> None:
        self.files_seen = 0
        self.skipped: List[Dict[str, str]] = []
        self.degraded: List[Dict[str, str]] = []

    def skip(self, path: str, reason: str, detail: str) -> None:
        self.skipped.append({"file": path, "reason": reason, "detail": detail})

    def degrade(self, path: str, detail: str) -> None:
        self.degraded.append({"file": path, "detail": detail})

    @property
    def complete(self) -> bool:
        return not self.skipped

    def to_dict(self) -> Dict[str, Any]:
        return {
            "complete": self.complete,
            "files_seen": self.files_seen,
            "files_skipped": len(self.skipped),
            "skipped": list(self.skipped),
            "degraded": list(self.degraded),
        }


def empty() -> Dict[str, Any]:
    """Coverage block for results produced without tracking."""
    return Coverage().to_dict()
