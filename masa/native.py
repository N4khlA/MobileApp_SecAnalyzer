"""Native/binary analysis: ELF (.so) and Mach-O structure checks plus
string extraction used to feed the secret/crypto rules.

Structure checks are deliberately conservative: static analysis can prove
the *absence* of protections (non-PIE, no RELRO, executable stack,
unencrypted Mach-O) but cannot prove memory safety.
"""

import re
import struct
from typing import List

from .models import Finding
from .rules import BY_ID

# ------------------------------------------------------------------ strings

def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extract ASCII and UTF-16LE string runs from binary data using fast C-regex matching."""
    if not data:
        return []
    ascii_pattern = re.compile(b"[\x20-\x7e]{" + str(min_len).encode() + b",}")
    matches = [m.decode("ascii", "ignore") for m in ascii_pattern.findall(data)]

    utf16_pattern = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}")
    utf16_matches = [m.decode("utf-16-le", "ignore") for m in utf16_pattern.findall(data)]

    out = matches + utf16_matches
    seen = set()
    deduped = []
    for s in out:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped


# ------------------------------------------------------------------ ELF

ELF_PT_GNU_STACK = 0x6474e551
ELF_PT_GNU_RELRO = 0x6474e552
ELF_ET_EXEC = 2
PF_X = 1


SHT_DYNSYM = 11

# weak primitives, matched against imported symbol names (MD5_Init, EVP_sha1)
_WEAK_IMPORT = re.compile(r"(?i)(?<![A-Za-z0-9])(?:MD4|MD5|DES|RC4|SHA-?1|3DES)"
                          r"(?![A-Za-z0-9])")


def elf_imports(data):
    """Names of undefined dynamic symbols (.dynsym entries with st_shndx 0):
    what the library calls in other libraries, not what it implements."""
    try:
        is64 = data[4] == 2
        e = "<" if data[5] == 1 else ">"
        if is64:
            shoff = struct.unpack_from(e + "Q", data, 40)[0]
            shentsize, shnum = struct.unpack_from(e + "HH", data, 58)
        else:
            shoff = struct.unpack_from(e + "I", data, 32)[0]
            shentsize, shnum = struct.unpack_from(e + "HH", data, 46)
        secs = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if is64:
                (_n, typ, _f, _a, off, size, link, _i, _al,
                 entsize) = struct.unpack_from(e + "IIQQQQIIQQ", data, o)
            else:
                (_n, typ, _f, _a, off, size, link, _i, _al,
                 entsize) = struct.unpack_from(e + "IIIIIIIIII", data, o)
            secs.append((typ, off, size, link, entsize))
        names = set()
        for typ, off, size, link, entsize in secs:
            if typ != SHT_DYNSYM or not entsize or link >= len(secs):
                continue
            stroff, strsize = secs[link][1], secs[link][2]
            for j in range(1, size // entsize):
                so = off + j * entsize
                if is64:
                    st_name, _info, _other, shndx = struct.unpack_from(
                        e + "IBBH", data, so)
                else:
                    st_name, _v, _s, _info, _other, shndx = struct.unpack_from(
                        e + "IIIBBH", data, so)
                if shndx == 0 and 0 < st_name < strsize:
                    start = stroff + st_name
                    end = data.find(b"\0", start, stroff + strsize)
                    names.add(data[start:end if end >= 0 else stroff + strsize]
                              .decode("ascii", "replace"))
        return names
    except (struct.error, IndexError):
        return set()


def elf_info(data):
    """Inspect an ELF binary. Returns dict or None if not ELF."""
    if not data.startswith(b"\x7fELF"):
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    if is64:
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
    has_relro = False
    exec_stack = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, off)[0]
        if is64:
            p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
        else:
            p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
        if p_type == ELF_PT_GNU_RELRO:
            has_relro = True
        elif p_type == ELF_PT_GNU_STACK:
            exec_stack = bool(p_flags & PF_X)
    return {
        "format": "ELF64" if is64 else "ELF32",
        "type": "PIE/DSO" if e_type != ELF_ET_EXEC else "executable",
        "pie": e_type != ELF_ET_EXEC,
        "relro": has_relro,
        "exec_stack": exec_stack,
        "imports": sorted(elf_imports(data)),
        "strings": extract_strings(data),
    }


# ------------------------------------------------------------------ Mach-O

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC_32 = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF


def macho_info(data):
    """Inspect a Mach-O binary (fat or thin). Returns dict or None."""
    if len(data) < 4:
        return None
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64, 0xBEBAFECA, 0xBFBAFECA):
        slices = []
        is64_fat = magic in (FAT_MAGIC_64, 0xBFBAFECA)
        nfat = struct.unpack_from(">I", data, 4)[0]
        ent_size = 32 if is64_fat else 20
        for i in range(min(nfat, 64)):
            off = 8 + i * ent_size
            if off + ent_size > len(data):
                break
            cputype = struct.unpack_from(">I", data, off)[0]
            slice_off = struct.unpack_from(">I", data, off + 8)[0]
            slice_size = struct.unpack_from(">I", data, off + 12)[0]
            slices.append((cputype, slice_off, slice_size))
        info = {"format": "fat", "slices": len(slices)}
        for cputype, off, size in slices:
            sub = macho_info(data[off:off + size])
            if sub:
                info.setdefault("slices_detail", []).append(sub)
        return info
    if magic == MH_MAGIC_64 or magic == 0xCFFAEDFE:
        endian = ">" if magic == MH_MAGIC_64 else "<"
        is64 = True
    elif magic == MH_MAGIC_32 or magic == 0xCEFAEDFE:
        endian = ">" if magic == MH_MAGIC_32 else "<"
        is64 = False
    else:
        return None
    ncmds = struct.unpack_from(endian + "I", data, 16)[0]
    header_size = 32 if is64 else 28
    encrypted = None
    pos = header_size
    for _ in range(min(ncmds, 128)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        if cmdsize < 8:
            break
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cmd, cmdsize, cryptoff, cryptsize, cryptid: +16 in both the
            # 32- and 64-bit command (the 64-bit one only adds trailing pad)
            cryptid_off = pos + 16
            if cryptid_off + 4 <= len(data):
                encrypted = struct.unpack_from(endian + "I", data, cryptid_off)[0]
        pos += cmdsize
    return {
        "format": "Mach-O64" if is64 else "Mach-O32",
        "encrypted": bool(encrypted) if encrypted is not None else None,
        "ncmds": ncmds,
        "strings": extract_strings(data),
    }


# ------------------------------------------------------------------ checks

_STRUCTURAL_RULES = {key: BY_ID[rid] for key, rid in {
    "non_pie": "NAT-006", "no_relro": "NAT-007", "exec_stack": "NAT-008",
    "no_canary": "NAT-009", "no_arc": "NAT-010", "not_encrypted": "BIN-004",
}.items()}


def analyze_binary(data, filename):
    """Run structural + string checks over one binary blob.

    Returns (structure_info, findings)."""
    info = None
    findings = []
    if data.startswith(b"\x7fELF"):
        info = elf_info(data)
        if info is not None:
            if not info["pie"]:
                findings.append(Finding(_STRUCTURAL_RULES["non_pie"],
                                        file=filename,
                                        evidence_type="binary",
                                        extra={"binary_protection": "non_pie"}))
            if not info["relro"]:
                findings.append(Finding(_STRUCTURAL_RULES["no_relro"],
                                        file=filename,
                                        evidence_type="binary",
                                        extra={"binary_protection": "no_relro"}))
            if info["exec_stack"]:
                findings.append(Finding(_STRUCTURAL_RULES["exec_stack"],
                                        file=filename,
                                        evidence_type="binary",
                                        extra={"binary_protection": "exec_stack"}))
            _hardening_findings(info.get("strings", []), filename, findings,
                                check_arc=False)
            # a library that implements DES exports DES_*; one that uses it
            # imports DES_* from a crypto library
            for name in info["imports"]:
                if _WEAK_IMPORT.search(name):
                    findings.append(Finding(BY_ID["NAT-002"], file=filename,
                                            snippet=name, match=name,
                                            evidence_type="binary"))
    else:
        info = macho_info(data)
        if info is not None:
            _macho_findings(info, filename, findings)
    return info, findings


def _macho_findings(info, filename, findings):
    if info.get("format") == "fat":
        for sub in info.get("slices_detail", []):
            _macho_findings(sub, filename, findings)
        return
    if info.get("encrypted") is False:
        findings.append(Finding(_STRUCTURAL_RULES["not_encrypted"],
                                file=filename, evidence_type="binary",
                                extra={"binary_protection": "not_encrypted"}))
    _hardening_findings(info.get("strings", []), filename, findings,
                        check_arc=True)


def _has_symbol(strings, name):
    return any(name in s for s in strings)


def _hardening_findings(strings, filename, findings, check_arc):
    """Compiler hardening is visible through imported symbol names:
    -fstack-protector imports __stack_chk_fail, ARC imports objc_release."""
    if not _has_symbol(strings, "__stack_chk_fail") and \
            not _has_symbol(strings, "__stack_chk_guard"):
        findings.append(Finding(_STRUCTURAL_RULES["no_canary"],
                                file=filename, evidence_type="binary",
                                extra={"binary_protection": "no_canary"}))
    if check_arc and _has_symbol(strings, "objc_msgSend") and \
            not _has_symbol(strings, "objc_release"):
        findings.append(Finding(_STRUCTURAL_RULES["no_arc"],
                                file=filename, evidence_type="binary",
                                extra={"binary_protection": "no_arc"}))
