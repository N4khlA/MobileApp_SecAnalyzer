"""Size limits for archives before their contents are loaded into memory."""

MAX_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_ENTRY_SIZE = 256 * 1024 * 1024


def check_zip(zf):
    """Raise ValueError if a zip would expand beyond the limits above."""
    total = 0
    for info in zf.infolist():
        if info.file_size > MAX_ENTRY_SIZE:
            raise ValueError("archive entry too large: %s (%d bytes)" %
                             (info.filename, info.file_size))
        total += info.file_size
        if total > MAX_TOTAL_SIZE:
            raise ValueError("archive expands to more than 1 GiB")
