"""Android binary XML (AXML) parser and writer, dependency-free.

Inside APKs, resources such as AndroidManifest.xml are stored in a binary
XML format. This module implements a parser (used to read manifests) and a
minimal writer (used by the sample/demo fixtures).

Format reference (chunks):
   0x0001 string pool, 0x0100/0x0101 namespace start/end,
   0x0102 start element, 0x0103 end element, 0x0104 cdata,
   0x0180 resource map.
"""

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"

TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_BOOLEAN = 0x12

UTF8_FLAG = 0x0100


class Attribute:
    __slots__ = ("ns", "name", "dtype", "data", "raw")

    def __init__(self, ns, name, dtype, data, raw):
        self.ns = ns
        self.name = name
        self.dtype = dtype
        self.data = data
        self.raw = raw

    def value(self):
        if self.dtype == TYPE_STRING:
            return self.raw
        if self.dtype == TYPE_BOOLEAN:
            return bool(self.data)
        if self.dtype == TYPE_INT_DEC:
            if self.data >= 0x80000000:
                return self.data - 0x100000000
            return self.data
        if self.dtype == TYPE_INT_HEX:
            return "0x%08x" % self.data
        if self.dtype == TYPE_FLOAT:
            return struct.unpack("<f", struct.pack("<I", self.data))[0]
        return self.raw

    def to_dict(self):
        return {"ns": self.ns, "name": self.name, "value": self.value(),
                "dtype": self.dtype, "data": self.data, "raw": self.raw}


class Element:
    __slots__ = ("ns", "name", "attrs", "children", "text", "line")

    def __init__(self, ns, name, line=0):
        self.ns = ns
        self.name = name
        self.attrs = []
        self.children = []
        self.text = None
        self.line = line

    def get(self, name, default=None, ns=ANDROID_NS):
        for a in self.attrs:
            if a.name == name and (ns is None or a.ns == ns):
                return a.value()
        return default

    def findall(self, name):
        return [c for c in self.children if c.name == name]

    def find(self, name, ns=None):
        for c in self.children:
            if c.name == name and (ns is None or c.ns == ns):
                return c
        return None

    def to_xml(self, indent=0):
        pad = "  " * indent
        attrs = []
        for a in self.attrs:
            val = a.value()
            if isinstance(val, bool):
                val = "true" if val else "false"
            attrs.append('%s:%s="%s"' % (a.ns.split("/")[-1] if a.ns else "",
                                         a.name, _esc(val)))
        attr_txt = (" " + " ".join(attrs)) if attrs else ""
        lines = []
        if self.text is not None:
            lines.append('%s<%s%s>%s</%s>' % (pad, self.name, attr_txt,
                                              _esc(self.text), self.name))
        elif not self.children:
            lines.append("%s<%s%s/>" % (pad, self.name, attr_txt))
        else:
            lines.append("%s<%s%s>" % (pad, self.name, attr_txt))
            for c in self.children:
                lines.append(c.to_xml(indent + 1))
            lines.append("%s</%s>" % (pad, self.name))
        return "\n".join(lines)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ---------------------------------------------------------------- parsing

class _Pool:
    def __init__(self, strings, is_utf8):
        self.strings = strings
        self.is_utf8 = is_utf8

    def get(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return None


def _dec_utf16(data, pos):
    length = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    if length & 0x8000:
        high = length & 0x7FFF
        low = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        length = (high << 16) | low
    end = pos + length * 2
    return data[pos:end].decode("utf-16-le", "replace"), end + 2


def _dec_utf8(data, pos):
    b = data[pos]
    pos += 1
    if b & 0x80:
        b = ((b & 0x7F) << 8) | data[pos]
        pos += 1
    b = data[pos]
    pos += 1
    if b & 0x80:
        b = ((b & 0x7F) << 8) | data[pos]
        pos += 1
    end = pos + b
    return data[pos:end].decode("utf-8", "replace"), end + 1


def _read_string_pool(data, off, chunk_size):
    (count, style_count, flags, strings_start, _styles) = struct.unpack_from(
        "<IIIII", data, off + 8)
    is_utf8 = bool(flags & UTF8_FLAG)
    strings = []
    for i in range(count):
        so = struct.unpack_from("<I", data, off + 28 + i * 4)[0]
        s, _ = (_dec_utf8 if is_utf8 else _dec_utf16)(data, off + so)
        strings.append(s)
    return strings


def parse(data):
    """Parse AXML bytes into an Element tree (root)."""
    root = Element(None, "#document")
    stack = [root]
    pool = []
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
        if ctype == 0x0003:                      # document container: skip
            pos += 8
            continue
        if csize < 8 or pos + csize > n:
            break
        body = data[pos + hsize: pos + csize]
        if ctype == 0x0001:                      # string pool
            pool = _read_string_pool(data, pos, csize)
        elif ctype == 0x0102:                    # start element
            (line, _comment, ns_idx, name_idx,
             attr_start, attr_size, attr_count,
             _id_idx, _class_idx, _style_idx) = struct.unpack_from(
                "<IIIIHHHHHH", data, pos + 8)
            ns = pool[ns_idx] if 0 <= ns_idx < len(pool) else None
            name = pool[name_idx] if 0 <= name_idx < len(pool) else "?"
            el = Element(ns, name, line)
            abase = pos + 16 + attr_start
            for i in range(attr_count):
                ao = abase + i * attr_size
                ans, aname, araw, asize, res0, dtype, adata = struct.unpack_from(
                    "<IIIHBBi", data, ao)
                raw = pool[araw] if 0 <= araw < len(pool) else None
                el.attrs.append(Attribute(
                    pool[ans] if 0 <= ans < len(pool) else None,
                    pool[aname] if 0 <= aname < len(pool) else "?",
                    dtype, adata, raw))
            stack[-1].children.append(el)
            stack.append(el)
        elif ctype == 0x0103:                    # end element
            if len(stack) > 1:
                stack.pop()
        elif ctype == 0x0104:                    # cdata
            raw_idx = struct.unpack_from("<I", data, pos + 16)[0]
            if stack and 0 <= raw_idx < len(pool):
                stack[-1].text = pool[raw_idx]
        pos += csize
    return root


def looks_like_axml(data):
    return len(data) >= 8 and struct.unpack_from("<HHI", data, 0)[:2] == (0x0003, 0x0008)


# ---------------------------------------------------------------- writing

def _enc_utf8_string(s):
    b = s.encode("utf-8")
    u16len = len(s.encode("utf-16-le")) // 2
    out = bytearray()
    if u16len < 0x80:
        out.append(u16len)
    else:
        out.append((u16len >> 8) | 0x80)
        out.append(u16len & 0xFF)
    if len(b) < 0x80:
        out.append(len(b))
    else:
        out.append((len(b) >> 8) | 0x80)
        out.append(len(b) & 0xFF)
    out += b
    out.append(0)
    return bytes(out)


class Builder:
    """Builds AXML bytes from an Element tree (writer for fixtures)."""

    def __init__(self, namespaces=(("android", ANDROID_NS),)):
        self.strings = []
        self.index = {}
        self.namespaces = list(namespaces)

    def intern(self, s):
        if s is None:
            return -1
        idx = self.index.get(s)
        if idx is None:
            idx = len(self.strings)
            self.index[s] = idx
            self.strings.append(s)
        return idx

    def _collect(self, el):
        if isinstance(el, (list, tuple)):
            for child in el:
                self._collect(child)
            return
        self.intern(el.name)
        if el.ns:
            self.intern(el.ns)
        for a in el.attrs:
            self.intern(a.name)
            if a.ns:
                self.intern(a.ns)
            if a.raw is not None:
                self.intern(str(a.raw))
        if el.text is not None:
            self.intern(el.text)
        for c in el.children:
            self._collect(c)

    def build(self, root):
        if isinstance(root, Element):
            wrapper = Element(None, "#document")
            wrapper.children = [root]
            root = wrapper
        self._collect(root)
        pool = self._build_pool()
        body = bytearray()
        for prefix, uri in self.namespaces:
            body += self._ns_chunk(0x0100, self.intern(prefix), self.intern(uri))
        for el in (root.children if isinstance(root, Element) else root):
            body += self._element(el)
        for prefix, uri in reversed(self.namespaces):
            body += self._ns_chunk(0x0101, self.intern(prefix), self.intern(uri))
        header = struct.pack("<HHI", 0x0003, 0x0008, 8 + len(pool) + len(body))
        return header + pool + bytes(body)

    def _build_pool(self):
        data = bytearray()
        offsets = []
        for s in self.strings:
            offsets.append(len(data))
            data += _enc_utf8_string(s)
        while len(data) % 4:
            data.append(0)
        strings_start = 28 + 4 * len(self.strings)
        csize = strings_start + len(data)
        header = struct.pack("<HHIIIII", 0x0001, 0x001C, csize,
                             len(self.strings), 0, UTF8_FLAG, strings_start)
        h = header + struct.pack("<I", 0)  # styles start
        out = h + b"".join(struct.pack("<I", strings_start + o)
                           for o in offsets) + bytes(data)
        return out

    def _ns_chunk(self, ctype, prefix_idx, uri_idx):
        body = struct.pack("<IIII", 0, 0xFFFFFFFF, prefix_idx, uri_idx)
        return struct.pack("<HHI", ctype, 0x0010, 24) + body

    def _idx(self, name):
        idx = self.intern(name)
        return 0xFFFFFFFF if idx < 0 else idx

    def _attr_chunk(self, a):
        if a.dtype == TYPE_STRING:
            data = self.intern(a.raw)
            raw = self._idx(a.raw)
        elif a.dtype == TYPE_BOOLEAN:
            data = 1 if a.raw in (True, 1, "true", "1") else 0
            raw = 0xFFFFFFFF
        elif a.dtype == TYPE_INT_DEC:
            data = a.data if a.data is not None else int(a.raw)
            self.intern(str(data))
            a.raw = str(data)
            raw = self._idx(a.raw)
        return struct.pack("<IIIHBBi",
                           self._idx(a.ns), self._idx(a.name),
                           raw, 0x0014, 0, a.dtype, data)

    def _element(self, el):
        out = bytearray()
        attrs = b"".join(self._attr_chunk(a) for a in el.attrs)
        csize = 36 + len(attrs)
        out += struct.pack("<HHI", 0x0102, 0x0010, csize)
        out += struct.pack("<IIII", el.line, 0xFFFFFFFF,
                           self._idx(el.ns), self._idx(el.name))
        out += struct.pack("<HHHHHH", 0x0014, 0x0014, len(el.attrs),
                           0xFFFF, 0xFFFF, 0xFFFF)
        out += attrs
        for c in el.children:
            out += self._element(c)
        out += struct.pack("<HHI", 0x0103, 0x0010, 24)
        out += struct.pack("<IIII", el.line, 0xFFFFFFFF,
                           self._idx(el.ns), self._idx(el.name))
        return bytes(out)


def build(elements):
    """Build AXML bytes for a list of top-level Elements (usually one)."""
    root = Element(None, "#document")
    root.children = elements
    return Builder().build(root)
