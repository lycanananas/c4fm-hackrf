#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Statically translate the carved C-SKY V2 codec (codec/code.bin) into C (build/codec_gen.c).

The generated file is derived from the codec, so it lives in build/ and is never committed. The translator only knows
the C-SKY V2 (CK803 + DSP) instruction set; it uses the C-SKY binutils objdump to decode the instructions.

Control flow: each reachable instruction gets a label. Direct branches become gotos; returns, jsr and pop go through
a dispatcher switch over every address an indirect jump may reach (entry points, return addresses, code pointers).
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOLBIN = os.path.expanduser("~/toolchains/csky-elf/bin")

LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f]+)\s*\t(\S+)\s*(?:\t(.*))?$")


def tool(name):
    return os.path.join(os.environ.get("CSKY_BIN", TOOLBIN), "csky-elf-" + name)


class Disasm:
    """objdump over the code window, wrapped in a CK810E ELF (the codec uses CK810-style DSP instructions)."""

    def __init__(self, code, run):
        self.code, self.run = code, run
        self.tmp = tempfile.mkdtemp(prefix="cskygen")
        stub, elf = os.path.join(self.tmp, "s.o"), os.path.join(self.tmp, "c.o")
        cbin = os.path.join(self.tmp, "code.bin")
        open(cbin, "wb").write(code)
        subprocess.run([tool("as"), "-mcpu=ck810e", "-o", stub, "-"], input=b"nop\n", check=True)
        subprocess.run([tool("objcopy"), "--add-section", ".codec=" + cbin, "--set-section-flags",
                        ".codec=code,alloc,load,readonly", "--change-section-address", ".codec=0x%x" % run, stub, elf],
                       check=True, stderr=subprocess.DEVNULL)
        self.elf = elf
        self.ins = {}

    def dis(self, start=None, stop=None):
        cmd = [tool("objdump"), "-d", "-j", ".codec", self.elf]
        if start is not None:
            cmd += ["--start-address=0x%x" % start, "--stop-address=0x%x" % stop]
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
        got = {}
        for ln in out.splitlines():
            m = LINE.match(ln)
            if not m:
                continue
            addr, hx, mn, ops = int(m.group(1), 16), m.group(2), m.group(3), (m.group(4) or "")
            ops = ops.split("//")[0].strip()
            ops = re.sub(r"\s*<[^>]*>", "", ops)
            got[addr] = (mn, ops, len(hx) // 2)
        return got


def split_ops(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def reg(s):
    s = s.strip()
    if s == "sp":
        return 14
    if s == "lr":
        return 15
    m = re.fullmatch(r"r(\d+)", s)
    if not m:
        raise ValueError("register %r" % s)
    return int(m.group(1))


def imm(s):
    return int(s.strip(), 0)


def reglist(ops):
    regs = []
    for part in ops:
        if "-" in part:
            a, b = part.split("-")
            regs += list(range(reg(a), reg(b) + 1))
        else:
            regs.append(reg(part))
    return regs


def mem_operand(s):
    """(rx, off) or (rx, ry, shift) from '(r1, 0x10)' or '(r1, r2 << 2)'."""
    inner = s.strip()[1:-1]
    a, b = [x.strip() for x in inner.split(",")]
    if "<<" in b:
        ry, sh = [x.strip() for x in b.split("<<")]
        return reg(a), reg(ry), int(sh, 0)
    return reg(a), imm(b)


BRANCH_COND = {"bt": "C", "bf": "!C"}
BRANCH_Z = {"bez": "== 0", "bnez": "!= 0", "bhz": "> 0", "blz": "< 0", "bhsz": ">= 0", "blsz": "<= 0"}
LOADS = {"ld.b": ("LDB", ""), "ld.h": ("LDH", ""), "ld.hs": ("LDH", "(uint32_t)(int16_t)"), "ld.w": ("LDW", ""),
         "ldr.b": ("LDB", ""), "ldr.h": ("LDH", ""), "ldr.hs": ("LDH", "(uint32_t)(int16_t)"), "ldr.w": ("LDW", ""),
         "ld.bs": ("LDB", "(uint32_t)(int8_t)"), "ldr.bs": ("LDB", "(uint32_t)(int8_t)")}
STORES = {"st.b": "STB", "st.h": "STH", "st.w": "STW", "str.b": "STB", "str.h": "STH", "str.w": "STW"}


def two_or_three(ops):
    """rz, rx, ry for 'op rz, rx, ry' or 'op rz, rx' (rz = rz op rx)."""
    if len(ops) == 3:
        return reg(ops[0]), reg(ops[1]), ops[2]
    return reg(ops[0]), reg(ops[0]), ops[1]


def translate(addr, mn, ops_s, size):
    """C statements for one instruction. Returns (code, kind, target): kind in
    'seq', 'goto' (unconditional), 'cond' (conditional, falls through), 'call', 'ret', 'ijump', 'icall', 'trap'."""
    o = split_ops(ops_s)
    nxt = addr + size
    R = lambda n: "r[%d]" % n  # noqa: E731

    def rr(x):
        return R(reg(x))

    if mn in ("br",):
        return "", "goto", imm(o[0])
    if mn in BRANCH_COND:
        t = imm(o[0])
        return "if (%s) goto L_%x;" % (BRANCH_COND[mn], t), "cond", t
    if mn in BRANCH_Z:
        t = imm(o[1])
        return "if ((int32_t)%s %s) goto L_%x;" % (rr(o[0]), BRANCH_Z[mn], t), "cond", t
    if mn == "bsr":
        return "r[15] = 0x%xu;" % nxt, "call", imm(o[0])
    if mn == "jsr":
        return "pc = %s; r[15] = 0x%xu;" % (rr(o[0]), nxt), "icall", None
    if mn == "jmp":
        return "pc = %s;" % rr(o[0]), "ijump", None
    if mn == "rts":
        return "pc = r[15];", "ijump", None
    if mn == "push":
        regs = reglist(o)
        s = "r[14] -= %d;" % (4 * len(regs))
        for i, n in enumerate(regs):
            s += " STW(r[14] + %d, r[%d]);" % (4 * i, n)
        return s, "seq", None
    if mn == "pop":
        regs = reglist(o)
        s = ""
        for i, n in enumerate(regs):
            s += "r[%d] = LDW(r[14] + %d); " % (n, 4 * i)
        s += "r[14] += %d; pc = r[15];" % (4 * len(regs))
        return s, "ijump", None
    if mn in LOADS:
        fn, cast = LOADS[mn]
        m = mem_operand(o[1])
        a = "%s + %d" % (R(m[0]), m[1]) if len(m) == 2 else "%s + (%s << %d)" % (R(m[0]), R(m[1]), m[2])
        return "%s = %s%s(%s);" % (rr(o[0]), cast, fn, a), "seq", None
    if mn in STORES:
        m = mem_operand(o[1])
        a = "%s + %d" % (R(m[0]), m[1]) if len(m) == 2 else "%s + (%s << %d)" % (R(m[0]), R(m[1]), m[2])
        return "%s(%s, %s);" % (STORES[mn], a, rr(o[0])), "seq", None
    if mn == "lrw":
        return "%s = 0x%xu;" % (rr(o[0]), imm(o[1]) & 0xFFFFFFFF), "seq", None
    if mn == "movi":
        return "%s = 0x%xu;" % (rr(o[0]), imm(o[1]) & 0xFFFFFFFF), "seq", None
    if mn == "movih":
        return "%s = 0x%xu;" % (rr(o[0]), (imm(o[1]) << 16) & 0xFFFFFFFF), "seq", None
    if mn == "mov":
        return "%s = %s;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "mvc":
        return "%s = C;" % rr(o[0]), "seq", None
    if mn == "mvcv":
        return "%s = !C;" % rr(o[0]), "seq", None
    if mn in ("addi", "subi"):
        op = "+" if mn == "addi" else "-"
        if len(o) == 2:
            return "%s %s= %du;" % (rr(o[0]), op, imm(o[1])), "seq", None
        return "%s = %s %s %du;" % (rr(o[0]), rr(o[1]), op, imm(o[2])), "seq", None
    simple = {"addu": "+", "subu": "-", "and": "&", "or": "|", "xor": "^", "mult": "*"}
    if mn in simple:
        z, x, y = two_or_three(o)
        return "r[%d] = r[%d] %s %s;" % (z, x, simple[mn], rr(y)), "seq", None
    if mn == "andn":
        z, x, y = two_or_three(o)
        return "r[%d] = r[%d] & ~%s;" % (z, x, rr(y)), "seq", None
    if mn == "nor":
        z, x, y = two_or_three(o)
        return "r[%d] = ~(r[%d] | %s);" % (z, x, rr(y)), "seq", None
    if mn in ("andi", "ori", "xori"):
        op = {"andi": "&", "ori": "|", "xori": "^"}[mn]
        return "%s = %s %s 0x%xu;" % (rr(o[0]), rr(o[1]), op, imm(o[2])), "seq", None
    if mn == "mulsh":
        z, x, y = two_or_three(o)
        return "r[%d] = (uint32_t)((int32_t)(int16_t)r[%d] * (int32_t)(int16_t)%s);" % (z, x, rr(y)), "seq", None
    if mn == "addc":
        z, x, y = two_or_three(o)
        return ("{ uint64_t t = (uint64_t)r[%d] + %s + C; r[%d] = (uint32_t)t; C = (uint32_t)(t >> 32); }"
                % (x, rr(y), z)), "seq", None
    if mn == "subc":
        z, x, y = two_or_three(o)
        return ("{ uint32_t a = r[%d], b = %s; uint64_t t = (uint64_t)a - b - (C ? 0 : 1); r[%d] = (uint32_t)t;"
                " C = (t >> 32) == 0; }" % (x, rr(y), z)), "seq", None
    if mn in ("lsli", "lsri", "asri", "rotli"):
        z, x, n = reg(o[0]), reg(o[1]), imm(o[2])
        if mn == "lsli":
            e = "r[%d] << %d" % (x, n)
        elif mn == "lsri":
            e = "r[%d] >> %d" % (x, n)
        elif mn == "asri":
            e = "(uint32_t)((int32_t)r[%d] >> %d)" % (x, n)
        else:
            e = "(r[%d] << %d) | (r[%d] >> %d)" % (x, n, x, (32 - n) & 31) if n else "r[%d]" % x
        return "r[%d] = %s;" % (z, e), "seq", None
    if mn in ("lsl", "lsr", "asr"):
        z, x, y = two_or_three(o)
        f = {"lsl": "SHL", "lsr": "SHR", "asr": "SAR"}[mn]
        return "r[%d] = %s(r[%d], %s);" % (z, f, x, rr(y)), "seq", None
    if mn in ("zextb", "zexth", "sextb", "sexth"):
        cast = {"zextb": "(uint8_t)", "zexth": "(uint16_t)", "sextb": "(uint32_t)(int8_t)",
                "sexth": "(uint32_t)(int16_t)"}[mn]
        return "%s = %s%s;" % (rr(o[0]), cast, rr(o[1])), "seq", None
    if mn in ("zext", "sext"):
        z, x, msb, lsb = reg(o[0]), reg(o[1]), imm(o[2]), imm(o[3])
        w = msb - lsb + 1
        if mn == "zext":
            mask = (1 << w) - 1
            return "r[%d] = (r[%d] >> %d) & 0x%xu;" % (z, x, lsb, mask), "seq", None
        return "r[%d] = (uint32_t)((int32_t)(r[%d] << %d) >> %d);" % (z, x, 31 - msb, 31 - msb + lsb), "seq", None
    if mn in ("bclri", "bseti"):
        if len(o) == 2:
            z = x = reg(o[0])
            n = imm(o[1])
        else:
            z, x, n = reg(o[0]), reg(o[1]), imm(o[2])
        if mn == "bclri":
            return "r[%d] = r[%d] & ~0x%xu;" % (z, x, 1 << n), "seq", None
        return "r[%d] = r[%d] | 0x%xu;" % (z, x, 1 << n), "seq", None
    if mn == "bmaski":
        n = imm(o[1])
        return "%s = 0x%xu;" % (rr(o[0]), (1 << n) - 1 if n < 32 else 0xFFFFFFFF), "seq", None
    if mn == "btsti":
        return "C = (%s >> %d) & 1;" % (rr(o[0]), imm(o[1])), "seq", None
    if mn == "cmphsi":
        return "C = %s >= 0x%xu;" % (rr(o[0]), imm(o[1])), "seq", None
    if mn == "cmphs":
        return "C = %s >= %s;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "cmplti":
        return "C = (int32_t)%s < %d;" % (rr(o[0]), imm(o[1])), "seq", None
    if mn == "cmplt":
        return "C = (int32_t)%s < (int32_t)%s;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "cmpnei":
        return "C = %s != 0x%xu;" % (rr(o[0]), imm(o[1])), "seq", None
    if mn == "cmpne":
        return "C = %s != %s;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "tst":
        return "C = (%s & %s) != 0;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn in ("inct", "incf"):
        cond = "C" if mn == "inct" else "!C"
        return "if (%s) %s = %s + %du;" % (cond, rr(o[0]), rr(o[1]), imm(o[2])), "seq", None
    if mn in ("ixh", "ixw"):
        sh = 1 if mn == "ixh" else 2
        return "%s = %s + (%s << %d);" % (rr(o[0]), rr(o[1]), rr(o[2]), sh), "seq", None
    if mn == "abs":
        return "%s = (int32_t)%s < 0 ? 0u - %s : %s;" % (rr(o[0]), rr(o[1]), rr(o[1]), rr(o[1])), "seq", None
    if mn == "ff1":
        return "%s = CLZ(%s);" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "ff0":
        return "%s = CLZ(~%s);" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "divs":
        return ("%s = DIVS(%s, %s);" % (rr(o[0]), rr(o[1]), rr(o[2]))), "seq", None
    if mn == "divu":
        return ("%s = DIVU(%s, %s);" % (rr(o[0]), rr(o[1]), rr(o[2]))), "seq", None
    if mn.startswith("xtrb") and len(mn) == 5:
        n = int(mn[4])
        return "%s = (%s >> %d) & 0xFF; C = %s != 0;" % (rr(o[0]), rr(o[1]), 24 - 8 * n, rr(o[0])), "seq", None
    # DSP: HI/LO accumulator. LOW keeps LO widened so mflos can saturate.
    if mn == "muls":
        return "ACC = (int64_t)(int32_t)%s * (int32_t)%s; LOW = (int32_t)ACC;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "mulsa":
        return "ACC += (int64_t)(int32_t)%s * (int32_t)%s; LOW = (int32_t)ACC;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn == "mulss":
        return "ACC -= (int64_t)(int32_t)%s * (int32_t)%s; LOW = (int32_t)ACC;" % (rr(o[0]), rr(o[1])), "seq", None
    if mn in ("mulsha", "mulshs"):
        op = "+" if mn == "mulsha" else "-"
        return ("LOW %s= (int32_t)(int16_t)%s * (int32_t)(int16_t)%s; SETLO((uint32_t)LOW);"
                % (op, rr(o[0]), rr(o[1]))), "seq", None
    if mn == "mfhi":
        return "%s = (uint32_t)((uint64_t)ACC >> 32);" % rr(o[0]), "seq", None
    if mn == "mflo":
        return "%s = (uint32_t)ACC;" % rr(o[0]), "seq", None
    if mn == "mflos":
        return "%s = SAT32(LOW);" % rr(o[0]), "seq", None
    if mn == "mthi":
        return "ACC = (int64_t)(((uint64_t)%s << 32) | (uint32_t)ACC);" % rr(o[0]), "seq", None
    if mn == "mtlo":
        return "SETLO(%s); LOW = (int32_t)%s;" % (rr(o[0]), rr(o[0])), "seq", None
    return 'TRAP(0x%xu, "%s %s");' % (addr, mn, ops_s.replace('"', "'")), "trap", None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--codec", default=os.path.join(ROOT, "codec"))
    ap.add_argument("-o", "--out", default=os.path.join(ROOT, "build", "codec_gen.c"))
    a = ap.parse_args()
    desc = json.load(open(os.path.join(a.codec, "codec.json")))
    code = open(os.path.join(a.codec, "code.bin"), "rb").read()
    run = desc["run"]
    d = Disasm(code, run)
    ins = d.dis()

    # roots: entry points and the code pointers the codec keeps in literal pools
    roots = [run + off for off in desc["entries"].values()]
    lo, hi = run, run + len(code)
    ptrs = set()
    for i in range(0, len(code) - 3, 2):
        mn = ins.get(run + i)
        if mn and mn[0] == "lrw":
            v = imm(split_ops(mn[1])[1]) & 0xFFFFFFFF
            if lo <= v < hi and not v & 1:
                ptrs.add(v)
    reach, work, dispatch, missing = {}, list(roots), set(roots), 0
    while work:
        pc = work.pop()
        while pc not in reach:
            if pc not in ins:
                missing += 1
                ins.update(d.dis(pc, min(pc + 0x400, hi)))
                if pc not in ins:
                    sys.exit("cannot decode at 0x%x" % pc)
            mn, ops, size = ins[pc]
            c, kind, tgt = translate(pc, mn, ops, size)
            reach[pc] = (mn, ops, size, c, kind, tgt)
            if kind in ("goto", "cond", "call") and tgt is not None:
                work.append(tgt)
            if kind == "call" or kind == "icall":
                dispatch.add(pc + size)
            if kind in ("goto", "ijump", "trap"):
                break
            pc += size
    # code pointers that land on reachable code are possible indirect targets; follow the ones not yet seen
    for p in sorted(ptrs):
        if p in ins and ins[p][0] == "push":
            dispatch.add(p)
            work.append(p)
    while work:
        pc = work.pop()
        while pc not in reach:
            if pc not in ins:
                ins.update(d.dis(pc, min(pc + 0x400, hi)))
            mn, ops, size = ins[pc]
            c, kind, tgt = translate(pc, mn, ops, size)
            reach[pc] = (mn, ops, size, c, kind, tgt)
            if kind in ("goto", "cond", "call") and tgt is not None:
                work.append(tgt)
            if kind in ("call", "icall"):
                dispatch.add(pc + size)
            if kind in ("goto", "ijump", "trap"):
                break
            pc += size

    traps = [(p, v[0], v[1]) for p, v in reach.items() if v[4] == "trap"]
    out = ["/* Generated by tools/gen_codec_c.py from codec %s (build %d). Derived from the codec: never commit. */"
           % (desc["name"], desc["tag"]), '#include "cskyrt.h"', "",
           "int codec_run(cpu_t *cpu, uint32_t pc)", "{",
           "\tuint32_t *r = cpu->r; uint32_t C = cpu->c; int64_t ACC = cpu->acc; int64_t LOW = cpu->low;",
           "\tuint64_t budget = cpu->budget;", "dispatch:",
           "\tif (pc == RET_MAGIC) { cpu->c = C; cpu->acc = ACC; cpu->low = LOW; return 0; }",
           "\tif (budget-- == 0) { cpu->pc = pc; return -2; }",
           "\tswitch (pc) {"]
    for p in sorted(dispatch):
        if p in reach:
            out.append("\tcase 0x%xu: goto L_%x;" % (p, p))
    out += ["\tdefault: cpu->pc = pc; return -1;", "\t}"]
    for p in sorted(reach):
        mn, ops, size, c, kind, tgt = reach[p]
        line = "L_%x: %s" % (p, c)
        if kind == "goto":
            line += " goto L_%x;" % tgt
        elif kind == "call":
            line += " goto L_%x;" % tgt
        elif kind in ("ijump", "icall"):
            line += " goto dispatch;"
        line += "\t/* %s %s */" % (mn, ops)
        out.append(line)
        nxt = p + size
        if kind in ("seq", "cond") and nxt not in reach:
            out.append("\tgoto L_%x;" % nxt)  # cannot happen: fallthrough is always reached
    out += ["}", ""]
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    open(a.out, "w").write("\n".join(out))
    print("%d instructions, %d dispatch targets, %d resyncs, %d traps -> %s"
          % (len(reach), len(dispatch), missing, len(traps), a.out))
    for t in traps[:20]:
        print("  trap 0x%x: %s %s" % t)


if __name__ == "__main__":
    main()
