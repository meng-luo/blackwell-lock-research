#!/usr/bin/env python3
"""nvrx.py -- nvriscv-2.0 decode-coverage analyzer (READ-ONLY).

Extracts an executable segment from a (possibly truncated) RISC-V ELF, rebuilds a
minimal ELF64/riscv so llvm-objdump can decode it, then reports:

  * raw decode coverage (known vs <unknown>)
  * opcode / funct3 / funct7 / quadrant histograms of the undecoded words
  * data-run detection (llvm prints long byte runs for undecodable regions)
  * recursive-descent reachability from the entry point (+ constant-folded
    lui/addi/auipc -> jr targets), so misalignment garbage is excluded from
    the statistics
  * self-consistency checks: branch/jal target alignment, auipc+addi -> string,
    prologue/epilogue pairing

Subcommands
  info     <elf>                      program headers / truncation check
  extract  <elf> <out.bin>            raw segment bytes + sidecar .json
  analyze  <elf> [opts]               the report
  sweep    <elf> [opts]               recursive descent, seed discovery dump

Only files named on the command line are written.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import struct
import subprocess
import sys

_RUSTLIB = os.environ.get(
    "LLVM_RUSTLIB",
    os.path.expanduser(r"~\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib"),
)
OBJDUMP = os.environ.get(
    "LLVM_OBJDUMP",
    os.path.join(_RUSTLIB, "bin", "llvm-objdump.exe"),
)
EM_RISCV = 243

# Feature sets, cheap -> exhaustive.  "rv64i" is what --triple=riscv64 gives you.
FEATURE_SETS = collections.OrderedDict([
    ("bare", ""),                                        # what plain --triple=riscv64 is
    ("c", "+c"),
    ("ma", "+m,+a"),
    ("imac", "+m,+a,+c,+zicsr,+zifencei"),
    ("imac_b", "+m,+a,+c,+b,+zicsr,+zifencei"),
    ("max", "+m,+a,+c,+b,+f,+d,+zicsr,+zifencei,+zicond,+zicntr,+zihintpause,"
            "+zihintntl,+zicbom,+zicboz,+zicbop,+zcmop,+zcb,+zcmp,+zawrs,+zacas,"
            "+zalrsc,+zaamo,+zabha,+zfa,+zfh,+zmmul,+zbkb,+zbkc,+zbkx,+zkt"),
])


# --------------------------------------------------------------------- ELF bits
class Phdr:
    __slots__ = ("type", "flags", "off", "vaddr", "paddr", "filesz", "memsz", "align")

    def rx(self):
        return bool(self.flags & 1)  # PF_X

    def __repr__(self):
        fl = "".join(c for c, b in zip("RWX", (4, 2, 1)) if self.flags & b)
        return (f"PH({self.type} {fl} off={self.off:#x} vaddr={self.vaddr:#x} "
                f"filesz={self.filesz:#x})")


class Elf:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise SystemExit(f"{path}: not ELF")
        if d[4] != 2 or d[5] != 1:
            raise SystemExit(f"{path}: only ELF64-LE supported")
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", d, 16)
        self.phdrs = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            if o + 56 > len(d):
                break
            p = Phdr()
            (p.type, p.flags, p.off, p.vaddr, p.paddr, p.filesz, p.memsz,
             p.align) = struct.unpack_from("<IIQQQQQQ", d, o)
            self.phdrs.append(p)

    def loads(self):
        return [p for p in self.phdrs if p.type == 1]

    def shdr_table_intact(self):
        if self.e_shoff == 0 or self.e_shnum == 0:
            return False
        return self.e_shoff + self.e_shnum * self.e_shentsize <= len(self.data)

    def seg_bytes(self, p):
        return self.data[p.off:p.off + p.filesz]


def pick_exec(e: Elf, want_vaddr=None, want_index=None):
    """Choose the executable PT_LOAD.  want_index counts only PT_LOAD entries."""
    loads = e.loads()
    if want_index is not None:
        return loads[want_index]
    if want_vaddr is not None:
        return next(p for p in loads if p.vaddr == want_vaddr)
    cands = [p for p in loads if p.rx()]
    if not cands:
        raise SystemExit("no executable PT_LOAD")
    return max(cands, key=lambda p: p.filesz)


def build_minimal_elf(payload: bytes, vaddr: int, outpath: str, name=".text"):
    """ELF64/riscv64, one RX PT_LOAD at file offset 0x1000.

    Offset 0x1000 keeps the payload clear of the ELF/PHDR headers.  (The source
    images put their code segment at p_offset=0 overlapping the header; a naive
    copy makes llvm-objdump start decoding the ELF magic and it never resyncs.)
    """
    FOFF = 0x1000
    shstr = b"\x00" + name.encode() + b"\x00.shstrtab\x00"
    n1 = 1
    n2 = 1 + len(name) + 1
    shstr_off = (FOFF + len(payload) + 7) & ~7
    shoff = (shstr_off + len(shstr) + 7) & ~7
    buf = bytearray(shoff + 3 * 64)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into("<16sHHIQQQIHHHHHH", buf, 0, ident, 2, EM_RISCV, 1, vaddr,
                     64, shoff, 0, 64, 56, 1, 64, 3, 2)
    struct.pack_into("<IIQQQQQQ", buf, 64, 1, 5, FOFF, vaddr, vaddr,
                     len(payload), len(payload), 0x1000)
    buf[FOFF:FOFF + len(payload)] = payload
    buf[shstr_off:shstr_off + len(shstr)] = shstr
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + 64, n1, 1, 6, vaddr, FOFF,
                     len(payload), 0, 0, 4, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + 128, n2, 3, 0, 0, shstr_off,
                     len(shstr), 0, 0, 1, 0)
    with open(outpath, "wb") as f:
        f.write(buf)
    return outpath


# --------------------------------------------------------------- objdump driver
# llvm-objdump riscv output:  "  addr: <hex word(s)> \t<mnem>\t<operands>"
# The hex field is the *instruction word in value order* for 4-byte insns
# ("93000f37" == lui t5,0x93000) and the halfword value for 2-byte insns.
_LINE = re.compile(r"^\s*([0-9a-f]{4,16}):\s+([0-9a-f ]+?)\s{2,}(.*)$")
_LINE2 = re.compile(r"^\s*([0-9a-f]{4,16}):\s+([0-9a-f ]+?)\s*\t(.*)$")


def run_objdump(elfpath, mattr=""):
    cmd = [OBJDUMP, "-d", "--triple=riscv64"]
    if mattr:
        cmd.append("--mattr=" + mattr)
    cmd.append(elfpath)
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return p.stdout, p.stderr, p.returncode


def parse_disasm(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] not in "0123456789abcdef":
            continue
        m = _LINE.match(line) or _LINE2.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = m.group(2).replace(" ", "")
        rest = m.group(3).strip()
        if not rest:
            rest = ""
        parts = rest.split(None, 1)
        mn = parts[0] if parts else ""
        ops = parts[1].strip() if len(parts) > 1 else ""
        nbytes = len(raw) // 2
        out.append(dict(addr=addr, raw=raw, mnem=mn, ops=ops, size=nbytes,
                        unknown=(mn == "<unknown>" or mn == ""),
                        datarun=(mn == "<unknown>" and nbytes > 4)))
    return out


def word_of(insn):
    """32-bit instruction word.  Handles both the 4-byte and the 2-byte form."""
    raw = insn["raw"]
    if len(raw) <= 8:
        return int(raw, 16)
    # long data run: take the leading 8 hex digits
    return int(raw[:8], 16)


# ------------------------------------------------- RISC-V scratch decoding (raw)
def rv_len(b, i):
    if i + 2 > len(b):
        return 2
    if (b[i] & 3) != 3:
        return 2
    if (b[i] & 0x1f) == 0x1f:
        return 8 if (b[i + 1] & 3) == 3 else 6   # >=48-bit encodings
    return 4


def rv_word(b, i):
    n = rv_len(b, i)
    if n >= 4 and i + 4 <= len(b):
        return struct.unpack_from("<I", b, i)[0], n
    if i + 2 <= len(b):
        return struct.unpack_from("<H", b, i)[0], n
    return 0, n


def sign(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _c_cj_imm(w):
    """CJ format immediate (c.j): imm[11|4|9:8|10|6|7|3:1|5]."""
    imm = (((w >> 12) & 1) << 11) | (((w >> 11) & 1) << 4) | \
          (((w >> 9) & 3) << 8) | (((w >> 8) & 1) << 10) | \
          (((w >> 7) & 1) << 6) | (((w >> 6) & 1) << 7) | \
          (((w >> 3) & 7) << 1) | (((w >> 2) & 1) << 5)
    return sign(imm, 12)


def _c_cb_imm(w):
    """CB format immediate (c.beqz / c.bnez): imm[8|4:3] + imm[7:6|2:1|5]."""
    imm = (((w >> 12) & 1) << 8) | (((w >> 10) & 3) << 3) | \
          (((w >> 5) & 3) << 6) | (((w >> 3) & 3) << 1) | (((w >> 2) & 1) << 5)
    return sign(imm, 9)


def cf_class(w, n, addr):
    """Classify control flow from the raw encoding.

    Returns (kind, targets) where kind in
      {'seq','jmp','br','ind','ret','stop'} and targets is a tuple of ints.
    """
    if n == 2:
        q = w & 3
        f3 = (w >> 13) & 7
        if q == 1:
            if f3 == 5:   # c.j
                return "jmp", (addr + _c_cj_imm(w),)
            if f3 == 1:   # c.jal on rv32, c.addiw on rv64 (not a branch here)
                return "seq", ()
            if f3 in (6, 7):  # c.beqz / c.bnez
                return "br", (addr + _c_cb_imm(w),)
            return "seq", ()
        if q == 2:
            b12 = (w >> 12) & 1
            if f3 == 4:
                rs1 = (w >> 7) & 0x1F
                rs2 = (w >> 2) & 0x1F
                if b12 and rs2 == 0:
                    return ("ret", ()) if rs1 == 1 else ("ind", ())
                if not b12 and rs2 == 0:
                    return ("ind", ()) if rs1 else ("stop", ())
            return "seq", ()
        return "seq", ()
    if n != 4:
        return "stop", ()
    op = w & 0x7F
    if op == 0x6F:                      # jal
        imm = ((w >> 31) << 20) | (((w >> 12) & 0xFF) << 12) | \
              (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3FF) << 1)
        return "jmp", (addr + sign(imm, 21),)
    if op == 0x63:                      # branch
        imm = ((w >> 31) << 12) | (((w >> 7) & 1) << 11) | \
              (((w >> 25) & 0x3F) << 5) | (((w >> 8) & 0xF) << 1)
        return "br", (addr + sign(imm, 13),)
    if op == 0x67:                      # jalr
        rd = (w >> 7) & 0x1F
        rs1 = (w >> 15) & 0x1F
        imm = sign(w >> 20, 12)
        if rd == 0 and rs1 == 1 and imm == 0:
            return "ret", ()
        return ("ind" if rd or rs1 else "stop"), ()
    if op == 0x73:                      # SYSTEM
        f3 = (w >> 12) & 7
        if f3 == 0:
            fn = w >> 20
            if fn in (0x102, 0x302, 0x002, 0x105, 0x007):   # sret/mret/uret/wfi/sfence
                return ("ind" if fn in (0x102, 0x302, 0x002) else "seq"), ()
        return "seq", ()
    return "seq", ()


# ------------------------------------------------------- constant propagation
def const_step(w, n, regs, addr):
    """Very small abstract interpreter: reg -> int, used only to resolve jr targets."""
    if n != 4:
        return
    op = w & 0x7F
    rd = (w >> 7) & 0x1F
    rs1 = (w >> 15) & 0x1F
    imm20 = sign(w >> 12, 20)
    if op == 0x37:                      # lui
        regs[rd] = (imm20 << 12) & 0xFFFFFFFFFFFFFFFF
    elif op == 0x17:                    # auipc
        regs[rd] = (addr + ((imm20 << 12) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    elif op in (0x13,):                 # addi
        f3 = (w >> 12) & 7
        if f3 == 0 and rs1 in regs:
            regs[rd] = (regs[rs1] + sign(w >> 20, 12)) & 0xFFFFFFFFFFFFFFFF
        else:
            regs.pop(rd, None)
    elif op == 0x1B:                    # addiw
        f3 = (w >> 12) & 7
        v = regs.get(rs1)
        if f3 == 0 and v is not None:
            regs[rd] = (v + sign(w >> 20, 12)) & 0xFFFFFFFF
        else:
            regs.pop(rd, None)
    elif op in (0x33, 0x3B, 0x03):      # ALU / load: destroys the constant in rd
        regs.pop(rd, None)
    elif op in (0x67, 0x6F):            # jalr/jal write rd too
        regs.pop(rd, None)


# ------------------------------------------------------------------- analysis
class Seg:
    """One executable region, decoded at several feature levels."""

    def __init__(self, payload, vaddr, name="", entry=None):
        self.b = payload
        self.vaddr = vaddr
        self.name = name
        self.entry = entry if (entry is not None and vaddr <= entry < vaddr + len(payload)) \
            else vaddr
        self.lo = vaddr
        self.hi = vaddr + len(payload)
        self.lens = self._lengths()

    def _lengths(self):
        b = self.b
        lens = []
        i = 0
        while i + 2 <= len(b):
            n = rv_len(b, i)
            lens.append(n)
            i += n
        return lens

    def boundaries(self):
        """Set of every 2-byte-granular offset that is a linear-sweep insn start."""
        s = set()
        o = 0
        for n in self.lens:
            s.add(self.vaddr + o)
            o += n
        return s

    def at_offset(self, addr):
        o = addr - self.vaddr
        return self.b[o:o + 16] if 0 <= o < len(self.b) else b""

    def index_of(self, addr):
        """Map addr -> index into self.lens, or None if not a boundary."""
        o = addr - self.vaddr
        if o < 0 or o >= len(self.b):
            return None
        r = 0
        for k, n in enumerate(self.lens):
            if r == o:
                return k
            r += n
        return None


def decode_linear(seg: Seg, mattr=""):
    """objdump linear sweep over the segment.  Returns (insns, stderr)."""
    tmp = os.path.join(os.environ.get("TEMP", "."), f"_nvrx_{os.getpid()}.elf")
    build_minimal_elf(seg.b, seg.vaddr, tmp)
    try:
        out, err, rc = run_objdump(tmp, mattr)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    insns = parse_disasm(out)
    return insns, err


def reachable(seg: Seg, insns, seeds=None, const_fold=True):
    """Recursive descent over the decoded stream.

    llvm already gives us a globally consistent instruction-boundary grid for the
    whole segment (it steps by the length it decoded), so we can walk that grid and
    prune everything not reachable from the entry point / jump-table constants.
    """
    by_addr = {i["addr"]: i for i in insns}
    if seeds is None:
        seeds = [seg.entry]
    # constant-fold scan (linear, not path sensitive) to recover jr targets
    if const_fold:
        regs = {}
        for i in insns:
            if i["unknown"]:
                regs.clear()
                continue
            w = word_of(i)
            const_step(w, i["size"], regs, i["addr"])
            kind, _ = cf_class(w, i["size"], i["addr"])
            if kind == "ind" and i["size"] == 4 and (w & 0x7F) == 0x67:
                rs1 = (w >> 15) & 0x1F
                t = regs.get(rs1)
                if t is not None and seg.lo <= t < seg.hi:
                    seeds.append(t)
    seen = set()
    work = [s for s in seeds if s in by_addr]
    while work:
        a = work.pop()
        if a in seen:
            continue
        i = by_addr.get(a)
        if i is None:
            continue
        seen.add(a)
        if i["unknown"]:
            continue
        w = word_of(i)
        kind, tgts = cf_class(w, i["size"], a)
        if kind == "seq":
            nxt = a + i["size"]
            if nxt in by_addr:
                work.append(nxt)
        elif kind in ("jmp", "br"):
            for t in tgts:
                if t in by_addr:
                    work.append(t)
            if kind == "br":
                nxt = a + i["size"]
                if nxt in by_addr:
                    work.append(nxt)
        # ind/ret/stop: path ends
    return seen


def hist_pct(counter, total, top=None):
    items = counter.most_common(top)
    return [{"key": k, "n": v, "pct": (100.0 * v / total if total else 0.0)}
            for k, v in items]


def unknown_profile(insns, total_unknown, samples=6):
    op = collections.Counter()
    f3 = collections.Counter()
    f7 = collections.Counter()
    op_f3 = collections.Counter()
    op_len = collections.Counter()
    ex = collections.defaultdict(list)
    for i in insns:
        if not i["unknown"]:
            continue
        w = word_of(i)
        n = i["size"]
        if n == 2:
            key = f"C.q{w & 3}.f3{(w >> 13) & 7}"
            op[key] += 1
            ex[key].append((hex(i["addr"]), i["raw"]))
            continue
        o = w & 0x7F
        op[hex(o)] += 1
        op_len[(hex(o), n)] += 1
        f3[(hex(o), (w >> 12) & 7)] += 1
        f7[(hex(o), (w >> 25) & 0x7F)] += 1
        op_f3[((hex(o), (w >> 12) & 7))] += 1
        if len(ex[hex(o)]) < samples:
            ex[hex(o)].append((hex(i["addr"]), i["raw"]))
    return dict(
        opcode=hist_pct(op, total_unknown),
        op_funct3=hist_pct(f3, total_unknown, 40),
        op_funct7=hist_pct(f7, total_unknown, 40),
        op_len=hist_pct(op_len, total_unknown, 40),
        samples={k: v for k, v in ex.items()},
    )


def isa_profile(insns):
    """Which extensions actually show up in the decoded stream.

    NOTE: llvm's RISC-V printer renders RVC instructions with their *uncompressed*
    aliases (0x4515 -> "li a0, 5", 0x8082 -> "ret"), so compressed instructions must
    be counted by encoded size, not by a "c." prefix.
    """
    mn = collections.Counter()
    e = collections.Counter()
    for i in insns:
        if i["unknown"]:
            continue
        mn[i["mnem"]] += 1
        if i["size"] == 2:
            e["C(16-bit)"] += 1
        elif i["size"] > 4:
            e["len>4"] += 1
    for m, c in mn.items():
        if m in ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
                 "mulw", "divw", "divuw", "remw", "remuw"):
            e["M"] += c
        if m.startswith(("lr.", "sc.", "amoadd", "amoswap", "amoxor", "amoand",
                         "amoor", "amomin", "amomax", "amominu", "amomaxu")):
            e["A"] += c
        if m in ("fence", "fence.i", "fence.tso", "pause", "fencei"):
            e["fence/Zifencei"] += c
        if m in ("csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci",
                 "csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci", "csrr"):
            e["Zicsr"] += c
        if m in ("sext.w", "zext.w", "sext.b", "sext.h", "zext.h", "rol", "ror",
                 "rori", "rolw", "rorw", "roriw", "andn", "orn", "xnor", "min",
                 "max", "minu", "maxu", "clz", "ctz", "cpop", "rev8", "orc.b",
                 "bset", "bclr", "binv", "bext", "bseti", "bclri", "binvi",
                 "bexti", "sh1add", "sh2add", "sh3add", "add.uw", "slli.uw"):
            e["B/Zb*"] += c
        if m in ("fld", "fsd", "flw", "fsw", "fld", "fmv.d.x", "fmv.x.d"):
            e["D/F"] += c
    return dict(mnemonics=mn.most_common(40), by_ext=dict(e))


def page_stats(seg: Seg, insns, page=0x1000):
    """Per-page token / unknown / printable-byte density, to separate code from rodata."""
    pages = collections.defaultdict(lambda: dict(tokens=0, unknown=0, nbytes=0))
    for i in insns:
        k = (i["addr"] - seg.vaddr) // page
        p = pages[k]
        p["tokens"] += 1
        p["nbytes"] += i["size"]
        if i["unknown"]:
            p["unknown"] += 1
    out = []
    for k in sorted(pages):
        lo = seg.vaddr + k * page
        chunk = seg.b[k * page:(k + 1) * page]
        printable = sum(1 for c in chunk if 32 <= c < 127 or c in (9, 10, 13))
        p = pages[k]
        out.append(dict(lo=hex(lo), tokens=p["tokens"], unknown=p["unknown"],
                        coverage_pct=100.0 * (p["tokens"] - p["unknown"]) / p["tokens"]
                        if p["tokens"] else 0.0,
                        printable_pct=100.0 * printable / len(chunk) if chunk else 0.0))
    return out


def branch_alignment(seg: Seg, insns, boundaries, memmap=None):
    """Are direct control-transfer targets landing on instruction boundaries?"""
    st = collections.Counter()
    ex = collections.defaultdict(list)
    for i in insns:
        if i["unknown"]:
            continue
        w = word_of(i)
        kind, tgts = cf_class(w, i["size"], i["addr"])
        if kind not in ("jmp", "br"):
            continue
        st["insns"] += 1
        for t in tgts:
            st["total"] += 1
            if t in boundaries:
                st["on_boundary"] += 1
                continue
            region, o = (memmap.find(t) if memmap else (None, None))
            if region is None:
                st["unmapped"] += 1
                if len(ex["unmapped"]) < 8:
                    ex["unmapped"].append([hex(i["addr"]), hex(t), i["mnem"]])
            elif t & 1:
                st["odd_addr"] += 1
                if len(ex["odd"]) < 8:
                    ex["odd"].append([hex(i["addr"]), hex(t), i["mnem"]])
            else:
                st["mapped_not_boundary"] += 1
                if len(ex["not_boundary"]) < 12:
                    ex["not_boundary"].append([hex(i["addr"]), hex(t), i["mnem"]])
    return dict(st), dict(ex)


GPR_ABI = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
           "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
           "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
           "t3", "t4", "t5", "t6"]
GPR = set(GPR_ABI) | {f"x{i}" for i in range(32)} | {"fp"}
_NUM = r"-?(?:0x[0-9a-fA-F]+|\d+)"


def parse_ops(ops):
    """Split llvm operand text into typed tokens.

    Each token: ('reg', name) | ('imm', int) | ('mem', imm, base) | ('other', text)
    """
    out = []
    if not ops:
        return out
    depth = 0
    cur = ""
    parts = []
    for ch in ops:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    for p in parts:
        p = p.strip()
        if not p:
            continue
        m = re.match(r"^(?P<imm>" + _NUM + r")?\((?P<base>[a-z][a-z0-9]*)\)$", p)
        if m:
            imm = int(m.group("imm"), 0) if m.group("imm") else 0
            out.append(("mem", imm, m.group("base")))
        elif re.match(r"^" + _NUM + r"$", p):
            out.append(("imm", int(p, 0)))
        elif p in GPR:
            out.append(("reg", p))
        else:
            out.append(("other", p))
    return out


def reg_num(name):
    if name in GPR_ABI:
        return GPR_ABI.index(name)
    if name == "fp":
        return 8
    if name.startswith("x"):
        try:
            return int(name[1:])
        except ValueError:
            return -1
    return -1


def _looks_like_text(blob):
    txt = blob.split(b"\x00")[0]
    if len(txt) < 6:
        return None
    if all(32 <= c < 127 or c in (9, 10) for c in txt):
        return txt.decode("latin1")
    return None


class MemMap:
    """All PT_LOAD segments, so an address can be resolved to a mapped region."""

    def __init__(self, elf, only_exec=False):
        self.regions = []
        for k, p in enumerate(elf.loads()):
            n = max(0, min(len(elf.data), p.off + p.filesz) - p.off)
            self.regions.append(dict(idx=k, lo=p.vaddr, hi=p.vaddr + n,
                                     data=elf.data[p.off:p.off + n],
                                     exec=bool(p.flags & 1), w=bool(p.flags & 2),
                                     name=("RX" if p.flags & 1 else "RW")))

    def find(self, addr):
        for r in self.regions:
            if r["lo"] <= addr < r["hi"]:
                return r, addr - r["lo"]
        return None, None


def auipc_base(addr, printed_imm):
    """llvm-objdump prints auipc's raw 20-bit field; the real delta is imm<<12."""
    v = printed_imm & 0xFFFFF
    if v & 0x80000:
        v -= 0x100000
    return (addr + (v << 12)) & 0xFFFFFFFFFFFFFFFF


def auipc_pairs(seg: Seg, insns, memmap=None):
    """auipc(+addi/lw/...) targets: mapped? in RX? on a string?

    A correct decode should make nearly every auipc+addi land inside one of the
    program's own PT_LOAD segments (that is what the compiler emitted it for).
    """
    by_addr = {i["addr"]: i for i in insns}
    st = collections.Counter()
    ex = collections.defaultdict(list)
    for i in insns:
        if i["unknown"] or i["mnem"] != "auipc":
            continue
        ops = parse_ops(i["ops"])
        if len(ops) < 2 or ops[0][0] != "reg" or ops[1][0] != "imm":
            continue
        rd, up = ops[0][1], ops[1][1]
        base = auipc_base(i["addr"], up)
        # find the consumer of rd (addi/addiw/load/store with rd as base)
        cons = None
        a2 = i["addr"] + i["size"]
        for _ in range(6):
            c = by_addr.get(a2)
            if c is None or c["unknown"]:
                break
            c_ops = parse_ops(c["ops"])
            hit = False
            if c["mnem"] in ("addi", "addiw") and len(c_ops) >= 3:
                if c_ops[1] == ("reg", rd) and c_ops[2][0] == "imm":
                    hit = True
            elif c["mnem"] in ("lw", "ld", "lb", "lbu", "lh", "lhu", "lwu",
                               "sw", "sd", "sb", "sh", "flw", "fld", "fsw", "fsd"):
                for t in c_ops:
                    if t[0] == "mem" and t[2] == rd:
                        hit = True
            elif c["mnem"] in ("c.lw", "c.ld", "c.sw", "c.sd", "c.addi", "c.addiw",
                               "c.lwsp", "c.ldsp", "c.flw", "c.fld"):
                for t in c_ops:
                    if t[0] == "mem" and t[2] == rd:
                        hit = True
                if c["mnem"] in ("c.addi", "c.addiw") and len(c_ops) >= 2 and \
                        c_ops[0] == ("reg", rd) and c_ops[1][0] == "imm":
                    hit = True
            if hit:
                cons = (c, c_ops)
                break
            a2 += c["size"]
        if cons is None:
            st["auipc_no_consumer"] += 1
            continue
        c, c_ops = cons
        off = 0
        for t in c_ops:
            if t[0] == "imm":
                off = t[1]
            elif t[0] == "mem":
                off = t[1]
        tgt = (base + off) & 0xFFFFFFFFFFFFFFFF
        st["pairs"] += 1
        region, o = (memmap.find(tgt) if memmap else (None, None))
        if region is None:
            st["unmapped"] += 1
            if len(ex["unmapped"]) < 8:
                ex["unmapped"].append((hex(i["addr"]), hex(tgt), c["mnem"]))
            continue
        st["mapped"] += 1
        st["in_rx" if region["exec"] else "in_rw"] += 1
        txt = _looks_like_text(region["data"][o:o + 64])
        if txt:
            st["on_string"] += 1
            if len(ex["string"]) < 10:
                ex["string"].append((hex(i["addr"]), hex(tgt), txt))
        elif tgt % 8 == 0:
            st["aligned8"] += 1
    n = st["pairs"] or 1
    return dict(pairs=st["pairs"], mapped=st["mapped"], in_rx=st["in_rx"],
                in_rw=st["in_rw"], on_string=st["on_string"],
                unmapped=st["unmapped"], no_consumer=st["auipc_no_consumer"],
                pct_mapped=100.0 * st["mapped"] / n,
                pct_in_rx=100.0 * st["in_rx"] / n,
                pct_on_string=100.0 * st["on_string"] / n,
                examples=dict(ex))


def func_pairs(insns):
    """Prologue (sp -= N) vs epilogue (ret) counts."""
    pro = epi = 0
    for i in insns:
        if i["unknown"]:
            continue
        mn, ops = i["mnem"], i["ops"]
        if mn == "c.addi16sp":
            pro += 1
        elif mn == "addi" and ops.startswith("sp, sp, -"):
            pro += 1
        if mn in ("ret", "c.ret"):
            epi += 1
        elif mn == "jalr" and ops.replace(" ", "") in ("zero,0(ra)", "x0,0(ra)"):
            epi += 1
        elif mn == "c.jr" and ops.strip() in ("ra", "x1"):
            epi += 1
    return dict(prologue=pro, epilogue=epi)


# ------------------------------------------------------------------------ CLI
def seg_from_args(a):
    e = Elf(a.elf)
    p = pick_exec(e, getattr(a, "vaddr", None), getattr(a, "seg", None))
    b = e.seg_bytes(p)
    va = p.vaddr
    st = getattr(a, "start", 0) or 0
    b = b[st:]
    va += st
    ln = getattr(a, "length", None)
    if ln:
        b = b[:ln]
    return e, p, b, va


def cmd_info(a):
    e = Elf(a.elf)
    print(a.elf)
    print(f"  size={len(e.data)} e_machine={e.e_machine} entry={e.e_entry:#x} "
          f"phnum={e.e_phnum} e_shoff={e.e_shoff:#x} shdr_intact={e.shdr_table_intact()}")
    for i, p in enumerate(e.phdrs):
        fl = "".join(c for c, bb in zip("RWX", (4, 2, 1)) if p.flags & bb)
        avail = max(0, min(len(e.data), p.off + p.filesz) - p.off)
        print(f"  PH[{i}] type={p.type} {fl:3s} off={p.off:#08x} vaddr={p.vaddr:#018x} "
              f"filesz={p.filesz:#07x} memsz={p.memsz:#07x} avail={avail:#x}")


def cmd_extract(a):
    e, p, b, va = seg_from_args(a)
    open(a.out, "wb").write(b)
    meta = dict(vaddr=va, size=len(b), src=a.elf, p_offset=p.off)
    open(a.out + ".json", "w").write(json.dumps(meta, indent=1))
    print(f"{a.out}: {len(b)} bytes @ {va:#x}")


def summarize(insns, seg, label):
    n = len(insns)
    unk = [i for i in insns if i["unknown"]]
    res = dict(label=label, total=n, unknown=len(unk), known=n - len(unk),
               coverage_pct=(100.0 * (n - len(unk)) / n if n else 0.0))
    reach = reachable(seg, insns)
    rinsns = [i for i in insns if i["addr"] in reach]
    runk = [i for i in rinsns if i["unknown"]]
    res["reach"] = dict(total=len(rinsns), unknown=len(runk),
                        known=len(rinsns) - len(runk),
                        coverage_pct=(100.0 * (len(rinsns) - len(runk)) / len(rinsns)
                                      if rinsns else 0.0),
                        tokens=len(rinsns),
                        bytes=sum(i["size"] for i in rinsns),
                        bytes_pct_of_segment=(100.0 * sum(i["size"] for i in rinsns)
                                              / len(seg.b) if seg.b else 0.0))
    return res, insns, rinsns


def cmd_analyze(a):
    e, p, b, va = seg_from_args(a)
    seg = Seg(b, va, os.path.basename(a.elf), entry=e.e_entry)
    memmap = MemMap(e)
    report = dict(elf=a.elf, vaddr=hex(va), size=len(b), entry=hex(e.e_entry),
                  p_offset=hex(p.off),
                  regions=[dict(name=r["name"], lo=hex(r["lo"]), hi=hex(r["hi"]),
                                size=len(r["data"])) for r in memmap.regions])
    bnd = seg.boundaries()
    sets = list(FEATURE_SETS.items())

    def run(label, mattr):
        insns, err = decode_linear(seg, mattr)
        s, _, rinsns = summarize(insns, seg, label)
        runk = [i for i in insns if i["unknown"]]
        s["unknown_profile_all"] = unknown_profile(runk, len(runk)) if runk else None
        rrunk = [i for i in rinsns if i["unknown"]]
        s["unknown_profile_reach"] = unknown_profile(rrunk, len(rrunk)) if rrunk else None
        st, ex = branch_alignment(seg, insns, bnd, memmap)
        s["branch"] = dict(stats=dict(st), examples=ex,
                           pct_on_boundary=(100.0 * st.get("on_boundary", 0) / st["total"]
                                            if st.get("total") else 0.0))
        s["auipc"] = auipc_pairs(seg, insns, memmap)
        s["func"] = func_pairs(insns)
        s["pages"] = page_stats(seg, insns)
        s["isa"] = isa_profile(insns)
        s["objdump_stderr"] = err.strip()[:400]
        au = s["auipc"]
        print(f"[{label:8s}] tok={s['total']:6d} unk={s['unknown']:6d} "
              f"cov={s['coverage_pct']:6.2f}% | reach tok={s['reach']['total']:6d} "
              f"cov={s['reach']['coverage_pct']:5.1f}% "
              f"({s['reach']['bytes_pct_of_segment']:4.1f}% bytes) | "
              f"br@bnd={s['branch']['pct_on_boundary']:5.2f}% "
              f"({st.get('on_boundary', 0)}/{st.get('total', 0)}) | "
              f"auipc mapped {au['mapped']}/{au['pairs']}={au['pct_mapped']:5.1f}% "
              f"(rx {au['in_rx']}, rw {au['in_rw']}) str={au['pct_on_string']:4.1f}% | "
              f"pro/epi={s['func']['prologue']}/{s['func']['epilogue']}")
        if err.strip():
            print("   stderr:", err.strip().splitlines()[0][:160])
        return s

    if a.mattr is None:
        per = {}
        for name, mattr in sets:
            per[name] = run(name, mattr)
        report["grid"] = per
    else:
        report["custom"] = run("custom", a.mattr)
    if a.json:
        open(a.json, "w").write(json.dumps(report, indent=1))
        print("wrote", a.json)


def cmd_sweep(a):
    e, p, b, va = seg_from_args(a)
    seg = Seg(b, va, entry=e.e_entry)
    insns, err = decode_linear(seg, a.mattr if a.mattr is not None else FEATURE_SETS["max"])
    reach = reachable(seg, insns)
    runk = [i for i in insns if i["addr"] in reach and i["unknown"]]
    print(f"linear tokens={len(insns)} reachable={len(reach)} reach_unknown={len(runk)}")
    if a.show:
        for i in sorted((x for x in insns if x["addr"] in reach),
                        key=lambda z: z["addr"])[:a.show]:
            print(f"  {i['addr']:#018x} {i['raw']:>10s} {i['mnem']:<10s} {i['ops']}")


def cmd_batch(a):
    """Run the coverage grid over every image matching a glob; emit a CSV summary."""
    import glob as globmod
    rows = []
    files = sorted(globmod.glob(a.pattern))
    if not files:
        raise SystemExit("no files matched " + a.pattern)
    for f in files:
        try:
            e = Elf(f)
            p = pick_exec(e, None, a.seg)
            b = e.seg_bytes(p)
            seg = Seg(b, p.vaddr, os.path.basename(f), entry=e.e_entry)
            memmap = MemMap(e)
            bnd = seg.boundaries()
            row = dict(file=os.path.basename(f), vaddr=hex(p.vaddr), size=len(b),
                       entry=hex(e.e_entry))
            for name in ("bare", "imac", "max"):
                insns, err = decode_linear(seg, FEATURE_SETS[name])
                unk = sum(1 for i in insns if i["unknown"])
                # code pages only: pages whose printable density < 40%
                pg = page_stats(seg, insns)
                code = [q for q in pg if q["printable_pct"] < 40.0]
                ct = sum(q["tokens"] for q in code)
                cu = sum(q["unknown"] for q in code)
                st, _ = branch_alignment(seg, insns, bnd, memmap)
                au = auipc_pairs(seg, insns, memmap)
                row[f"tok_{name}"] = len(insns)
                row[f"unk_{name}"] = unk
                row[f"cov_{name}"] = round(100.0 * (len(insns) - unk) / len(insns), 2)
                row[f"covcode_{name}"] = round(100.0 * (ct - cu) / ct, 2) if ct else 0.0
                row[f"br_{name}"] = round(100.0 * st.get("on_boundary", 0) / st["total"], 2) \
                    if st.get("total") else 0.0
                row[f"auipc_{name}"] = round(au["pct_mapped"], 1)
                row[f"str_{name}"] = round(au["pct_on_string"], 1)
                if name == "max":
                    row["codepages"] = len(code)
                    row["pro_epi"] = str(func_pairs(insns)["prologue"]) + "/" + \
                        str(func_pairs(insns)["epilogue"])
            rows.append(row)
            print(" ".join(f"{k}={v}" for k, v in row.items()))
        except Exception as ex:      # keep going: one bad image must not kill the batch
            print(f"{f}: FAILED {type(ex).__name__}: {ex}")
    if a.csv:
        cols = []
        for r in rows:
            for k in r:
                if k not in cols:
                    cols.append(k)
        with open(a.csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(",".join(cols) + "\n")
            for r in rows:
                fh.write(",".join(str(r.get(c, "")) for c in cols) + "\n")
        print("wrote", a.csv)


def add_common(x):
    x.add_argument("--seg", type=int, help="index among PT_LOAD entries")
    x.add_argument("--vaddr", type=lambda s: int(s, 0))
    x.add_argument("--start", type=lambda s: int(s, 0))
    x.add_argument("--length", type=lambda s: int(s, 0))


def main():
    ap = argparse.ArgumentParser(prog="nvrx")
    sp = ap.add_subparsers(dest="cmd", required=True)

    i = sp.add_parser("info")
    i.add_argument("elf")
    i.set_defaults(func=cmd_info)

    x = sp.add_parser("extract")
    x.add_argument("elf")
    x.add_argument("out")
    add_common(x)
    x.set_defaults(func=cmd_extract)

    x = sp.add_parser("analyze")
    x.add_argument("elf")
    add_common(x)
    x.add_argument("--json")
    x.add_argument("--mattr", help="use this feature string only instead of the grid")
    x.set_defaults(func=cmd_analyze)

    x = sp.add_parser("batch")
    x.add_argument("pattern")
    x.add_argument("--seg", type=int)
    x.add_argument("--csv")
    x.set_defaults(func=cmd_batch)

    x = sp.add_parser("sweep")
    x.add_argument("elf")
    add_common(x)
    x.add_argument("--mattr")
    x.add_argument("--show", type=int, default=0)
    x.set_defaults(func=cmd_sweep)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
