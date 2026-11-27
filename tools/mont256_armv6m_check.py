#!/usr/bin/env python3
"""Check and time zkn_mul_mont_256 for ARMv6-M under emulation.

    python3 tools/mont256_armv6m_check.py                 # the assembly
    python3 tools/mont256_armv6m_check.py --elf app.elf    # and the one of an app ELF
    python3 tools/mont256_armv6m_check.py -D ZKN_MONT256_NO_FIELD_PATHS

The assembly of src/zkn_mont/zkn_mont256_armv6m.S is run in a Cortex-M0+
emulator against a Python transcription of the C algorithm of zkn_mont256.c:
same accumulator, same final subtraction, so the comparison is bit for bit,
for reduced and unreduced operands, and with the result written over an
operand or over both (a squaring in place). With --elf, the zkn_mul_mont_256
linked in a device ELF runs on the same inputs: the assembly as it sits in the
image, or the C version if the image was built with -DZKN_MONT256_NO_ASM or
before the assembly existed.

The assembly has a path for the two curve fields and one for any modulus.
The moduli below go through both, and through the way back from the first to
the second: moduli that share n0, or all limbs but one, with a field.

It also counts cycles with the Cortex-M0+ timings (1 per instruction, 2 for a
load, a store or a taken branch, 1 + n for push/pop of n registers, 3 for
bl/pop pc), for the two multipliers the core can be built with: MULS in 1
cycle, or in 32. For the assembly, a modulus whose products do not all take
the same number of cycles is an error.

Needs clang (or arm-none-eabi-gcc), arm-none-eabi-ld/objcopy/nm, and the
Python packages unicorn and capstone.
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP)

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.join(HERE, "..", "src", "zkn_mont", "zkn_mont256_armv6m.S")

M32 = 0xFFFFFFFF
N = 8

MODULI = {
    "BN254 r (BabyJubjub field)": 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
    "BabyJubjub subgroup order": 0x060C89CE5C263405370A08B6D0302B0BAB3EEDB83920EE0A677297DC392126F1,
    "BLS12-381 r (Bandersnatch field)": 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    "Bandersnatch subgroup order": 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1,
    "2^256 - 189": (1 << 256) - 189,
    "2^255 - 19": (1 << 255) - 19,
    "small odd modulus": 0x10001,
    # Not the fields, and close to them: these must take the path of any modulus.
    "n0 of BN254 r, other limbs": (0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
                                   ^ (1 << 40)),
    "BN254 r but its top limb": (0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
                                 ^ (1 << 250)),
    "n0 of BLS12-381 r, other limbs": (1 << 255) + (0x1234567 << 32) + 1,
    "BLS12-381 r but its top limb": (0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
                                     ^ (1 << 225)),
}


def limbs(x):
    return [(x >> (32 * i)) & M32 for i in range(N)]


def from_limbs(l):
    return sum(v << (32 * i) for i, v in enumerate(l))


def n0_of(p):
    return (-pow(p, -1, 1 << 32)) & M32


def reference(a, b, p, n0):
    """zkn_mul_mont_256 of zkn_mont256.c, limb for limb."""
    A, B, P = limbs(a), limbs(b), limbs(p)
    t = [0] * (N + 1)
    for i in range(N):
        carry = 0
        for j in range(N):
            carry += A[j] * B[i] + t[j]
            t[j] = carry & M32
            carry >>= 32
        carry2 = t[N] + carry
        t[N] = carry2 & M32
        overflow = carry2 >> 32
        m = (t[0] * n0) & M32
        carry = (t[0] + m * P[0]) >> 32
        for j in range(1, N):
            carry += t[j] + m * P[j]
            t[j - 1] = carry & M32
            carry >>= 32
        carry += t[N]
        t[N - 1] = carry & M32
        t[N] = ((carry >> 32) + overflow) & M32
    tmp, borrow = [0] * N, 0
    for i in range(N):
        d = t[i] - P[i] - borrow
        tmp[i] = d & M32
        borrow = 1 if d < 0 else 0
    return from_limbs(t[:N] if t[N] < borrow else tmp)


class Machine:
    """A Cortex-M0+ with one code image, a data area and a stack."""
    CODE, DATA, STACK, STOP = 0x00010000, 0x20000000, 0x20010000, 0x000F0000

    def __init__(self, image, base, entry):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
        size = (len(image) + 0xFFF) & ~0xFFF
        self.uc.mem_map(base & ~0xFFF, size + 0x1000)
        self.uc.mem_write(base, image)
        self.uc.mem_map(self.DATA, 0x1000)
        self.uc.mem_map(self.STACK, 0x4000)
        self.uc.mem_map(self.STOP, 0x1000)
        self.entry = entry
        self.cycles = self.muls = self.instrs = 0
        self.prev = None
        self.low_sp = 0
        self.uc.hook_add(UC_HOOK_CODE, self._step)

    def _step(self, uc, addr, size, _):
        if self.STOP <= addr < self.STOP + 0x1000:
            return
        if self.prev is not None:
            p_addr, p_size, p_branch = self.prev
            if p_branch and addr != p_addr + p_size:
                self.cycles += 1                       # taken branch
        code = bytes(uc.mem_read(addr, size))
        ins = next(self.cs.disasm(code, addr), None)
        mn = ins.mnemonic if ins else ""
        cost, branch = 1, False
        if mn.startswith("mul"):
            self.muls += 1
        elif mn.startswith(("ldr", "str")):
            cost = 2
        elif mn in ("push", "pop"):
            regs = ins.op_str.count(",") + 1
            cost = 1 + regs + (2 if "pc" in ins.op_str else 0)
        elif mn == "bl":
            cost = 3
        elif mn in ("bx", "blx"):
            cost = 2
        elif mn.startswith("b"):
            branch = True
        self.cycles += cost
        self.instrs += 1
        self.prev = (addr, size, branch)
        sp = uc.reg_read(UC_ARM_REG_SP)
        if sp < self.low_sp:
            self.low_sp = sp

    def mul(self, a, b, p, n0, alias=None):
        """alias: None, 'a' (r = a), 'b' (r = b) or 'ab' (r = a = b, a squaring in place)."""
        uc = self.uc
        d = self.DATA
        ra, rb, rp, rr = d + 0x100, d + 0x140, d + 0x180, d + 0x1C0
        if alias == "a":
            rr = ra
        elif alias == "b":
            rr = rb
        elif alias == "ab":
            rb = rr = ra
        pack = lambda x: b"".join(v.to_bytes(4, "little") for v in limbs(x))
        uc.mem_write(d + 0x1C0, b"\xEE" * 32)
        uc.mem_write(ra, pack(a))
        uc.mem_write(rb, pack(b))
        uc.mem_write(rp, pack(p))
        sp = self.STACK + 0x3F00
        uc.mem_write(sp, n0.to_bytes(4, "little"))     # fifth argument
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_R0, rr)
        uc.reg_write(UC_ARM_REG_R1, ra)
        uc.reg_write(UC_ARM_REG_R2, rb)
        uc.reg_write(UC_ARM_REG_R3, rp)
        uc.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.cycles = self.muls = self.instrs = 0
        self.prev = None
        self.low_sp = sp
        uc.emu_start(self.entry | 1, self.STOP)
        out = bytes(uc.mem_read(rr, 32))
        intact = (bytes(uc.mem_read(rp, 32)) == pack(p)
                  and (alias in ("a", "ab") or bytes(uc.mem_read(ra, 32)) == pack(a))
                  and (alias in ("b", "ab") or bytes(uc.mem_read(rb, 32)) == pack(b)))
        return int.from_bytes(out, "little"), intact, sp - self.low_sp


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def halves(rng):
    """A 256-bit value whose 16-bit halves sit on the cases of a comparison."""
    pick = lambda: rng.choice((0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF, rng.getrandbits(16)))
    x = 0
    for i in range(N):
        lo = pick()
        hi = rng.choice((lo, pick(), pick()))                  # equal halves one time in three
        x |= ((hi << 16) | lo) << (32 * i)
    return x


def assemble(path, defines=()):
    tmp = tempfile.mkdtemp(prefix="mont256-")
    obj, elf, binf = (os.path.join(tmp, n) for n in ("m.o", "m.elf", "m.bin"))
    flags = ["-mcpu=cortex-m0plus", "-mthumb"] + [f"-D{d}" for d in defines]
    try:
        run(["clang", "--target=armv6m-none-eabi", *flags, "-c", path, "-o", obj])
    except (OSError, subprocess.CalledProcessError):
        run(["arm-none-eabi-gcc", *flags, "-c", path, "-o", obj])
    run(["arm-none-eabi-ld", "-Ttext=0x10000", "-e", "zkn_mul_mont_256", obj, "-o", elf])
    run(["arm-none-eabi-objcopy", "-O", "binary", elf, binf])
    return Machine(open(binf, "rb").read(), 0x10000, 0x10000), os.path.getsize(binf)


def from_elf(path):
    """The zkn_mul_mont_256 of a device ELF, with whatever it calls."""
    tmp = tempfile.mkdtemp(prefix="mont256-")
    binf = os.path.join(tmp, "app.bin")
    run(["arm-none-eabi-objcopy", "-O", "binary", "-j", ".text", path, binf])
    base = entry = None
    for line in run(["arm-none-eabi-objdump", "-h", path]).splitlines():
        f = line.split()
        if len(f) > 4 and f[1] == ".text":
            base = int(f[3], 16)
    for line in run(["arm-none-eabi-nm", path]).splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == "zkn_mul_mont_256":
            entry = int(f[0], 16) & ~1
    if base is None or entry is None:
        sys.exit(f"{path}: no .text or no zkn_mul_mont_256")
    # Device apps are linked at 0xc0d00000, a region an M-profile core never
    # executes from. The code is position independent (-fropi): run it lower.
    where = 0x00100000
    return Machine(open(binf, "rb").read(), where, where + (entry - base))


def cases(p, rng, count):
    edge = [0, 1, 2, p - 1, p, (p + 1) & ((1 << 256) - 1), (1 << 256) - 1, (1 << 256) % p,
            (1 << 255), M32, M32 << 224, 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000]
    for a in edge:
        for b in edge:
            yield a, b
    for _ in range(count):
        yield rng.randrange(p), rng.randrange(p)                  # reduced
    for _ in range(count // 4):
        yield rng.getrandbits(256), rng.getrandbits(256)           # anything
    for a in edge + [rng.randrange(p) for _ in range(count // 4)]:
        yield a, a                                                 # squarings
    for _ in range(count // 2):
        yield halves(rng), halves(rng)                             # halves equal, ordered both ways


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--asm", default=ASM)
    ap.add_argument("--elf", help="device ELF whose zkn_mul_mont_256 runs on the same inputs")
    ap.add_argument("--count", type=int, default=400, help="random products per modulus")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("-D", dest="defines", action="append", default=[], metavar="NAME",
                    help="define NAME when assembling, e.g. ZKN_MONT256_NO_FIELD_PATHS")
    args = ap.parse_args()

    asm, size = assemble(args.asm, args.defines)
    c = from_elf(args.elf) if args.elf else None
    rng = random.Random(args.seed)
    total = bad = 0
    table = []
    for name, p in MODULI.items():
        n0 = n0_of(p)
        fails = 0
        stats = {"asm": [0, 0, 0, 0, set()], "elf": [0, 0, 0, 0, set()]}   # cycles, muls, runs, stack, distinct counts
        for k, (a, b) in enumerate(cases(p, rng, args.count)):
            want = reference(a, b, p, n0)
            alias = (None, "a", "b")[k % 3]
            if a == b and k % 2:
                alias = "ab"                                       # zkn_sqr_mont_256(x, x)
            got, intact, stack = asm.mul(a, b, p, n0, alias)
            ok = got == want and intact
            s = stats["asm"]
            s[0] += asm.cycles; s[1] += asm.muls; s[2] += 1; s[3] = max(s[3], stack)
            s[4].add((asm.cycles, asm.muls))
            if c:
                got_c, intact_c, stack_c = c.mul(a, b, p, n0, alias)
                ok = ok and got_c == want and intact_c
                s = stats["elf"]
                s[0] += c.cycles; s[1] += c.muls; s[2] += 1; s[3] = max(s[3], stack_c)
                s[4].add((c.cycles, c.muls))
            # a reduced product is the Montgomery product
            if a < p and b < p and p > 1 and want != (a * b * pow(1 << 256, -1, p)) % p:
                ok = False
            total += 1
            if not ok:
                fails += 1
                if fails <= 3:
                    print(f"  MISMATCH {name}: a={a:064x} b={b:064x} alias={alias}")
        varies = len(stats["asm"][4]) != 1
        if varies:
            fails += 1
            print(f"  NOT CONSTANT {name}: {len(stats['asm'][4])} distinct cycle counts")
        bad += fails
        print(f"{'ok  ' if not fails else 'FAIL'} {name}")
        table.append((name, stats))
    print(f"\n{total} products, {bad} failures; assembly: {size} bytes of code")
    print(f"\n{'':4s} {'modulus':34s} {'MULS':>5s} {'cycles, MULS in 1':>18s} {'in 32':>7s} {'stack':>6s}")
    for name, stats in table:
        for label in ("asm", "elf"):
            cyc, muls, runs, stack, distinct = stats[label]
            if runs:
                c1, m = cyc / runs, muls / runs
                same = "" if len(distinct) == 1 else "  varies"
                print(f"{label:4s} {name:34s} {m:5.0f} {c1:18.0f} {c1 + 31 * m:7.0f} {stack:5d}B{same}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
