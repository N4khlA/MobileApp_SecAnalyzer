"""Binary plist (bplist00) parser and writer, dependency-free.

Used to read Info.plist / embedded.mobileprovision inside iOS apps and to
build the demo fixtures.
"""

import struct
from datetime import datetime, timedelta

MAGIC = b"bplist00"
_EPOCH = datetime(2001, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------- parsing

def _read_uint(data, off, size):
    return int.from_bytes(data[off:off + size], "big")


def loads(data):
    """Parse binary plist bytes into native Python objects."""
    if not isinstance(data, (bytes, bytearray)) or not bytes(data[:8]) == MAGIC:
        raise ValueError("not a binary plist")
    trailer = data[-32:]
    off_size = trailer[6]
    ref_size = trailer[7]
    num_objects = _read_uint(trailer, 8, 8)
    top_object = _read_uint(trailer, 16, 8)
    table_off = _read_uint(trailer, 24, 8)

    def read_int_at(pos, size):
        return int.from_bytes(data[pos:pos + size], "big")

    offsets = [read_int_at(table_off + i * off_size, off_size)
               for i in range(num_objects)]
    cache = {}

    def parse_obj(idx, depth=0):
        if idx in cache:
            return cache[idx]
        if depth > 64:
            raise ValueError("plist nesting too deep")
        off = offsets[idx]
        marker = data[off]
        top = marker >> 4
        low = marker & 0x0F
        if top == 0x0:
            return {0: None, 8: False, 9: True}.get(low, None)
        if top == 0x1:                       # int
            size = low + 1
            return read_int_at(off + 1, size)
        if top == 0x2:                       # real
            if low == 3:
                return struct.unpack(">d", data[off + 1:off + 9])[0]
            return struct.unpack(">f", data[off + 1:off + 5])[0]
        if top == 0x3:                       # date
            secs = struct.unpack(">d", data[off + 1:off + 9])[0]
            return _EPOCH + timedelta(seconds=secs)
        if top in (0x4, 0x5, 0x6, 0x8):      # data / ascii / utf16 / uid
            pos = off + 1
            count = low
            if low == 0x0F:
                size = (data[pos] & 0x0F) + 1
                count = read_int_at(pos + 1, size)
                pos += 1 + size
            if top == 0x4:
                return bytes(data[pos:pos + count])
            if top == 0x5:
                return data[pos:pos + count].decode("latin-1")
            if top == 0x6:
                return data[pos:pos + count * 2].decode("utf-16-be", "replace")
            return bytes(data[pos:pos + count])
        if top in (0xA, 0xD):                # array / dict
            pos = off + 1
            count = low
            if low == 0x0F:
                size = (data[pos] & 0x0F) + 1
                count = read_int_at(pos + 1, size)
                pos += 1 + size
            refs = [read_int_at(pos + i * ref_size, ref_size)
                    for i in range(count * (2 if top == 0xD else 1))]
            if top == 0xA:
                result = [parse_obj(r, depth + 1) for r in refs]
            else:
                keys = [parse_obj(r, depth + 1) for r in refs[:count]]
                vals = [parse_obj(r, depth + 1) for r in refs[count:]]
                result = dict(zip(keys, vals))
            cache[idx] = result
            return result
        raise ValueError("unknown plist object marker 0x%02x" % marker)

    return parse_obj(top_object)


# ---------------------------------------------------------------- writing

def _int_bytes(value):
    if value < 0:
        value &= (1 << 64) - 1
    if value < 0x100:
        return bytes([0x10, value])
    if value < 0x10000:
        return bytes([0x11]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([0x12]) + value.to_bytes(4, "big")
    return bytes([0x13]) + value.to_bytes(8, "big")


def _len_head(marker_base, length):
    """Object header with optional extended length integer."""
    if length < 15:
        return bytes([marker_base | length])
    return bytes([marker_base | 0x0F]) + _int_bytes(length)


def dumps(obj):
    """Serialize a dict/list/str/int/bool/float/bytes tree to bplist bytes."""
    order = []          # object blobs in serialization order (children first)
    memo_id = {}        # id(obj) -> object id
    str_memo = {}       # value -> object id
    top = None

    def alloc(blob):
        order.append(blob)
        return len(order) - 1

    def visit(o):
        oid = id(o)
        if oid in memo_id:
            return memo_id[oid]
        if isinstance(o, str):
            if o in str_memo:
                return str_memo[o]
            try:
                blob = o.encode("latin-1")
                base = 0x50
            except UnicodeEncodeError:
                blob = o.encode("utf-16-be")
                base = 0x60
            n = len(blob) if base == 0x50 else len(blob) // 2
            result = alloc(_len_head(base, n) + blob)
            str_memo[o] = result
            memo_id[oid] = result
            return result
        if isinstance(o, bool):
            result = alloc(bytes([0x09 if o else 0x08]))
            memo_id[oid] = result
            return result
        if isinstance(o, int):
            result = alloc(_int_bytes(o))
            memo_id[oid] = result
            return result
        if isinstance(o, float):
            result = alloc(bytes([0x23]) + struct.pack(">d", o))
            memo_id[oid] = result
            return result
        if isinstance(o, bytes):
            result = alloc(_len_head(0x40, len(o)) + o)
            memo_id[oid] = result
            return result
        if isinstance(o, (list, tuple)):
            for item in o:
                visit(item)
            refs = b"".join(bytes([memo_id[id(i)]]) for i in o)
            result = alloc(_len_head(0xA0, len(o)) + refs)
            memo_id[oid] = result
            return result
        if isinstance(o, dict):
            for k in o:
                visit(k)
            for v in o.values():
                visit(v)
            refs = b"".join(bytes([memo_id[id(k)]]) for k in o)
            refs += b"".join(bytes([memo_id[id(v)]]) for v in o.values())
            result = alloc(_len_head(0xD0, len(o)) + refs)
            memo_id[oid] = result
            return result
        raise TypeError("cannot serialize %r" % type(o))

    top = visit(obj)
    if len(order) > 255:
        raise ValueError("fixture writer supports at most 255 objects")
    ref_size = 1
    offsets = []
    cur = len(MAGIC)
    for blob in order:
        offsets.append(cur)
        cur += len(blob)
    if cur <= 0x100:
        off_size = 1
    elif cur <= 0x10000:
        off_size = 2
    else:
        off_size = 4
    body = b"".join(order)
    padding = (8 - (len(body) + len(MAGIC)) % 8) % 8
    table = b"".join(o.to_bytes(off_size, "big") for o in offsets)
    out = MAGIC + body + b"\x00" * padding + table
    trailer = (b"\x00" + b"\x00" + b"\x00" * 4 +   # unused, sort version, unused
               bytes([off_size]) + bytes([ref_size]) +
               len(order).to_bytes(8, "big") +
               top.to_bytes(8, "big") +
               (len(MAGIC) + len(body) + padding).to_bytes(8, "big"))
    return out + trailer.ljust(32, b"\x00")
