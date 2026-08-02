"""Dex string table extraction (Android classes.dex).

Decompilers (dex2jar + CFR, jadx, apktool) are preferred when installed;
when they are not available this module recovers the string constants from
the dex string table, which is where hardcoded secrets usually live.
"""

import struct

MAGIC = b"dex\n"


def _uleb128(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def dex_strings(data):
    """Return the list of strings stored in a dex file ([] if invalid)."""
    if not data.startswith(MAGIC):
        return []
    try:
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        string_ids_off = struct.unpack_from("<I", data, 60)[0]
        if string_ids_size == 0 or string_ids_size > 10_000_000:
            return []
        strings = []
        for i in range(string_ids_size):
            so = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            if so >= len(data):
                continue
            _utf16_len, pos = _uleb128(data, so)
            end = data.find(b"\x00", pos)
            if end == -1 or end - pos > 65536:
                continue
            raw = data[pos:end].replace(b"\xc0\x80", b"\x00")
            strings.append(raw.decode("utf-8", "surrogatepass"))
        return strings
    except (struct.error, IndexError):
        return []


def extract_naive(data, min_len=4):
    """Fallback raw byte-string extraction (ASCII runs)."""
    out = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin-1"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("latin-1"))
    return out
