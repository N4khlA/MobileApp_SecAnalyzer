"""Read APK/IPA archives and directory trees with size limits.

Entries that cannot be read are recorded in a Coverage object instead of being
dropped, so a damaged or hostile archive cannot quietly shrink the scan.
"""

import os
import zipfile
import zlib

from .coverage import TOO_LARGE, UNREADABLE, Coverage, human_size, is_media

MAX_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_ENTRY_SIZE = 256 * 1024 * 1024

# What zipfile raises for one damaged entry: bad CRC or size (BadZipFile),
# corrupt deflate data (zlib.error), truncation (EOFError), encryption
# (RuntimeError), unknown compression (NotImplementedError), bzip2/lzma data
# errors (OSError and its subclasses).
_ENTRY_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError,
                 NotImplementedError, OSError)


def check_zip(zf):
    """Raise ValueError if a zip would expand beyond the limits above.

    Declared sizes are trustworthy here: zipfile stops reading at the declared
    size and reports a CRC error if the real data is longer.
    """
    total = 0
    for info in zf.infolist():
        if info.file_size > MAX_ENTRY_SIZE:
            raise ValueError("archive entry too large: %s (%d bytes)" %
                             (info.filename, info.file_size))
        total += info.file_size
        if total > MAX_TOTAL_SIZE:
            raise ValueError("archive expands to more than 1 GiB")


def _describe(exc):
    text = str(exc).strip()
    return "%s: %s" % (type(exc).__name__, text) if text else type(exc).__name__


def read_zip(zf, coverage: Coverage):
    """Return {name: bytes} for every readable entry in an open ZipFile."""
    check_zip(zf)
    files = {}
    for info in zf.infolist():
        if info.is_dir():
            continue
        coverage.files_seen += 1
        try:
            files[info.filename] = zf.read(info)
        except _ENTRY_ERRORS as exc:
            coverage.skip(info.filename, UNREADABLE, _describe(exc))
    return files


def read_tree(root, coverage: Coverage, max_size=MAX_ENTRY_SIZE):
    """Return {relpath: bytes} for a directory, skipping media files."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            coverage.files_seen += 1
            if is_media(fn):
                continue
            try:
                size = os.path.getsize(full)
                if size > max_size:
                    coverage.skip(rel, TOO_LARGE, "%s exceeds the %s file limit"
                                  % (human_size(size), human_size(max_size)))
                    continue
                with open(full, "rb") as fh:
                    files[rel] = fh.read()
            except OSError as exc:
                coverage.skip(rel, UNREADABLE, _describe(exc))
    return files


def load(input_path, coverage: Coverage, max_size=MAX_ENTRY_SIZE):
    """Read a zip archive or a directory tree into memory."""
    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path) as zf:
            return read_zip(zf, coverage)
    if os.path.isdir(input_path):
        return read_tree(input_path, coverage, max_size)
    return {}
