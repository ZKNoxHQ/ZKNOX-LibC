#!/usr/bin/env python3
"""
gen_poseidon_opt.py — generates the Poseidon tables of the SW backend:
    src/zkn_mont/zkn_poseidon_opt_tables.h
    src/zkn_mont/zkn_poseidon_opt_tables.c

Parameter set: circomlib Poseidon, x^5 S-box, RF = 8, t = 2..8
(Poseidon-1 .. Poseidon-7), generated for the BN254 scalar field.

Everything is derived from the parameters, with no input file:
  1. round constants and MDS matrix from the Grain LFSR (Poseidon paper,
     hadeshash generate_parameters_grain.sage);
  2. the round constants moved through the linear layer, so that a partial
     round adds one constant instead of t (same algorithm and same values as
     the C of circomlibjs tools/poseidon_optimize_constants.js);
  3. optionally, sparse matrices for the last k partial rounds of an arity
     (the S and P of the same tool, generalized to k rounds);
  4. every element converted to Montgomery form (x * 2^256 mod q) and written
     as 8 little-endian 32-bit limbs, the in-memory format of zkn_mont256.

Speed against flash, per arity: k = 0 (default) keeps the dense MDS matrix in
every round and gives the smallest table, t*RF + RP + t^2 elements. Each
sparse round adds 2t - 2 elements (plus t^2 once) and saves (t - 1)^2
Montgomery multiplications per hash. k = RP is the fully optimized form of
circomlibjs.
    --sparse BN254:5=60,BN254:7=max     k for Poseidon-5 and Poseidon-7
    --sparse max                         every partial round of every table
The choice is written in the generated files; SPARSE below sets the default.

Two fields are emitted (INSTANCES below):
  BN254     the circomlib instance, t = 2..8;
  BLS12381  the same integers (constants and MDS generated for BN254)
            evaluated over the BLS12-381 scalar field. This is what the
            library computes when EdDSA / FROST run on Bandersnatch, whose
            base field is passed as the Montgomery context. It is not a
            hadeshash BLS12-381 parameter set. Only t = 6 (Poseidon-5), the
            arity those callers use.
Pushed constants and sparse matrices depend on the field (matrix inverses),
hence one table per (field, arity).

Usage, from the repository root:
  python3 tools/gen_poseidon_opt.py              rewrites the two files
  python3 tools/gen_poseidon_opt.py --check DIR  also compares the BN254
        tables with DIR/poseidon_constants.json and
        DIR/poseidon_constants_opt.json (js/node_modules/circomlibjs/src)
  python3 tools/gen_poseidon_opt.py --kat        prints known answers
        (reference permutation) for tests/test_poseidon_opt.c
  --out DIR writes the two files to DIR instead of src/zkn_mont.
After a change of --sparse, run `make test` and `make poseidon-diff`.

Python 3, standard library only.
"""
import json
import os
import sys

P_BN254 = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
P_BLS12381 = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

N_BITS = 254            # Grain parameters: those of the BN254 instance
RF = 8
RP = {2: 56, 3: 57, 4: 56, 5: 60, 6: 60, 7: 63, 8: 64}
R = 1 << 256

# (name, modulus, values of t generated, mask macro)
INSTANCES = [
    ("BN254", P_BN254, [2, 3, 4, 5, 6, 7, 8], "ZKN_POSEIDON_ARITIES"),
    ("BLS12381", P_BLS12381, [6], "ZKN_POSEIDON_BLS12381_ARITIES"),
]

# Sparse partial rounds per (field, number of inputs); 0 when absent.
# Example: {("BN254", 5): 60} makes Poseidon-5 over BN254 fully sparse.
SPARSE = {}


def sparse_rounds(name, t):
    k = SPARSE.get((name, t - 1), 0)
    assert 0 <= k <= RP[t], f"{name} Poseidon-{t - 1}: k must be in 0..{RP[t]}"
    return k


def parse_sparse(spec):
    """--sparse argument: 'max', or 'FIELD:N=K,...' with K a number or 'max'."""
    if spec == "max":
        for name, _, ts, _ in INSTANCES:
            for t in ts:
                SPARSE[(name, t - 1)] = RP[t]
        return
    for item in spec.split(","):
        key, k = item.split("=")
        name, n = key.split(":")
        n = int(n)
        assert any(name == i[0] and n + 1 in i[2] for i in INSTANCES), f"no table for {key}"
        SPARSE[(name, n)] = RP[n + 1] if k == "max" else int(k)


def mask_of(ts):
    return sum(1 << (t - 1) for t in ts)


# ── Grain LFSR ────────────────────────────────────────────────────────
class Grain:
    def __init__(self, t, rp):
        bits = []

        def push(value, width):
            bits.extend((value >> i) & 1 for i in range(width - 1, -1, -1))

        push(1, 2)        # field: GF(p)
        push(0, 4)        # S-box: x^alpha
        push(N_BITS, 12)
        push(t, 12)
        push(RF, 10)
        push(rp, 10)
        bits.extend([1] * 30)
        self.s = bits
        for _ in range(160):
            self._step()

    def _step(self):
        s = self.s
        b = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        s.pop(0)
        s.append(b)
        return b

    def bit(self):
        while True:
            first = self._step()
            second = self._step()
            if first:
                return second

    def integer(self, nbits):
        v = 0
        for _ in range(nbits):
            v = (v << 1) | self.bit()
        return v


_REFERENCE = {}


def reference_constants(t):
    """Round constants C[(RF+RP)*t] and MDS matrix M[t][t] of the BN254
    instance: the content of circomlibjs poseidon_constants.json."""
    if t in _REFERENCE:
        return _REFERENCE[t]
    p = P_BN254
    rp = RP[t]
    g = Grain(t, rp)
    c = []
    while len(c) < (RF + rp) * t:
        v = g.integer(N_BITS)
        if v < p:
            c.append(v)
    # Cauchy matrix M[i][j] = 1 / (x_i + y_j), x and y drawn from the stream.
    while True:
        r = [g.integer(N_BITS) % p for _ in range(2 * t)]
        if len(set(r)) != 2 * t:
            continue
        xs, ys = r[:t], r[t:]
        if any((x + y) % p == 0 for x in xs for y in ys):
            continue
        break
    m = [[pow(x + y, p - 2, p) for y in ys] for x in xs]
    _REFERENCE[t] = (c, m)
    return c, m


# ── Linear algebra over GF(q) ─────────────────────────────────────────
def mat_inv(a, q):
    n = len(a)
    b = [list(row) + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(a)]
    for col in range(n):
        piv = next(i for i in range(col, n) if b[i][col] % q)
        b[col], b[piv] = b[piv], b[col]
        inv = pow(b[col][col], q - 2, q)
        b[col] = [x * inv % q for x in b[col]]
        for i in range(n):
            if i != col and b[i][col]:
                f = b[i][col]
                b[i] = [(x - f * y) % q for x, y in zip(b[i], b[col])]
    return [row[n:] for row in b]


def mat_mul(a, b, q):
    n = len(a)
    return [[sum(a[i][k] * b[k][j] for k in range(n)) % q for j in range(n)] for i in range(n)]


def vec_mul_mat(v, a, q):
    n = len(v)
    return [sum(v[i] * a[i][j] for i in range(n)) % q for j in range(n)]


def mat_mul_vec(a, v, q):
    return [sum(x * y for x, y in zip(row, v)) % q for row in a]


def transpose(a):
    return [list(col) for col in zip(*a)]


# ── Optimized form (circomlibjs tools/poseidon_optimize_constants.js) ──
def convert_constants(t, c, m, q):
    rp = RP[t]
    minv = mat_inv(m, q)
    res = list(c[:t])
    for r in range(RF // 2 - 1):
        res += vec_mul_mat(c[(r + 1) * t:(r + 2) * t], minv, q)
    partial = []
    acc = list(c[(RF // 2 + rp) * t:(RF // 2 + rp + 1) * t])
    for r in range(RF // 2 + rp - 1, RF // 2 - 1, -1):
        accp = vec_mul_mat(acc, minv, q)
        partial.append(accp[0])
        accp[0] = 0
        acc = [(accp[k] + c[r * t + k]) % q for k in range(t)]
    res += vec_mul_mat(acc, minv, q)
    res += partial[::-1]
    for r in range(RF // 2 + rp, RF + rp - 1):
        res += vec_mul_mat(c[(r + 1) * t:(r + 2) * t], minv, q)
    return res


def sparse_factorize(m, q):
    n = len(m)
    m_hat = [[m[i][j] for j in range(1, n)] for i in range(1, n)]
    mp = [[(m[i][j] if (i > 0 and j > 0) else (1 if i == j == 0 else 0)) for j in range(n)]
          for i in range(n)]
    w = [m[i][0] for i in range(1, n)]
    wp = mat_mul_vec(mat_inv(m_hat, q), w, q)
    return mp, [m[0][0]] + wp + [m[0][k] for k in range(1, n)]


def calculate_ps(t, m, q, k):
    """Sparse matrices of the last k partial rounds, in the order the rounds
    use them, and the dense matrix P that replaces M in the round before."""
    sparse = []
    cur = m
    for _ in range(k):
        mp, s = sparse_factorize(cur, q)
        sparse.append(s)
        cur = mat_mul(m, mp, q)
    return cur, sparse[::-1]


def optimized_constants(t, q, k):
    """(C, S, M, P) over GF(q). C and M are those of circomlibjs
    poseidon_constants_opt.json; S (k rows of 2t - 1) and P are too when
    k = RP."""
    c, m = reference_constants(t)
    om = transpose(m)
    p, s = calculate_ps(t, om, q, k)
    return convert_constants(t, c, om, q), s, om, p


# ── The two permutations, used to check one against the other ─────────
def poseidon_reference(t, inputs, q, init=0, nout=1):
    c, m = reference_constants(t)
    rp = RP[t]
    st = [init % q] + [x % q for x in inputs]
    for r in range(RF + rp):
        st = [(x + c[r * t + i]) % q for i, x in enumerate(st)]
        if r < RF // 2 or r >= RF // 2 + rp:
            st = [pow(x, 5, q) for x in st]
        else:
            st[0] = pow(st[0], 5, q)
        st = mat_mul_vec(m, st, q)
    return st[:nout]


def poseidon_from_table(t, k, flat, q, inputs, init=0, nout=1):
    """The permutation as zkn_poseidon_soft.c runs it, reading the flat table
    of layout() with the same indices."""
    rp = RP[t]
    half = RF // 2
    c = 0
    mt = t * RF + rp
    pt = mt + t * t
    sp = pt + t * t

    def mix(st, m, rows):
        return [sum(flat[m + i * t + j] * st[j] for j in range(t)) % q for i in range(rows)] + st[rows:]

    st = [init % q] + [x % q for x in inputs]
    st = [(x + flat[c + i]) % q for i, x in enumerate(st)]
    c += t
    for r in range(half):
        st = [pow(x, 5, q) for x in st]
        st = [(x + flat[c + i]) % q for i, x in enumerate(st)]
        c += t
        st = mix(st, pt if (r == half - 1 and k == rp) else mt, t)
    for r in range(rp):
        st[0] = (pow(st[0], 5, q) + flat[c]) % q
        c += 1
        if r < rp - k:
            st = mix(st, pt if (r == rp - k - 1 and k > 0) else mt, t)
        else:
            s0 = flat[mt] * st[0] + sum(flat[sp + j - 1] * st[j] for j in range(1, t))
            for i in range(1, t):
                st[i] = (st[i] + st[0] * flat[sp + t - 1 + i - 1]) % q
            st[0] = s0 % q
            sp += 2 * t - 2
    for r in range(half - 1):
        st = [pow(x, 5, q) for x in st]
        st = [(x + flat[c + i]) % q for i, x in enumerate(st)]
        c += t
        st = mix(st, mt, t)
    st = [pow(x, 5, q) for x in st]
    return mix(st, mt, nout)[:nout]


# ── Table written for the C code ──────────────────────────────────────
def table_len(t, k):
    return t * RF + RP[t] + t * t + (t * t + k * (2 * t - 2) if k else 0)


def layout(t, k, tables):
    """One flat list per (field, arity):
         C  : t*RF + RP      constants, in the order the rounds add them
         MT : t * t          row i = coefficients of output i (MT[i][j] = M[j][i])
       and, when k > 0:
         PT : t * t          same convention                    (PT[i][j] = P[j][i])
         S  : k * (2t - 2)   sparse matrices of the last k partial rounds
       A sparse matrix of circomlibjs has 2t - 1 coefficients. The first one
       is M[0][0] in every round: it is not repeated, the code reads MT[0].
    """
    c, s, m, p = tables
    flat = list(c) + [m[j][i] for i in range(t) for j in range(t)]
    if k:
        flat += [p[j][i] for i in range(t) for j in range(t)]
        for row in s:
            assert row[0] == m[0][0]
            flat += row[1:]
    assert len(flat) == table_len(t, k)
    return flat


def limbs(x, q, montgomery=True):
    v = x * R % q if montgomery else x
    return ", ".join(f"0x{(v >> (32 * i)) & 0xFFFFFFFF:08x}u" for i in range(8))


NOTE = """\
 * GENERATED by tools/gen_poseidon_opt.py, do not edit.
 *
 * Poseidon tables of the SW backend (circomlib parameter set: x^5, RF = 8,
 * constants and MDS matrix from the Grain LFSR for the BN254 scalar field).
 * The round constants are moved through the linear layer: a partial round
 * adds one constant. The last k partial rounds of an arity may use sparse
 * matrices (k is chosen per arity when the tables are generated).
 *
 * Every element is in Montgomery form (x * 2^256 mod q), 8 little-endian
 * 32-bit limbs: the in-memory format of zkn_mont256, so the permutation
 * multiplies straight from flash.
 *
 * One array per (field, arity), laid out as
 *     C  : t*RF + RP       round constants, in the order they are added
 *     MT : t * t           MDS matrix, row i = coefficients of output i
 * and, when k > 0,
 *     PT : t * t           matrix of the round before the sparse ones
 *     S  : k * (2t - 2)    sparse matrices, t - 1 row coefficients then
 *                          t - 1 column coefficients (the corner is MT[0])
 *
 * Fields:
 *     BN254     the circomlib instance, Poseidon-1 .. Poseidon-7.
 *     BLS12381  the same integers evaluated over the BLS12-381 scalar field:
 *               what EdDSA / FROST compute on Bandersnatch. Not a hadeshash
 *               BLS12-381 parameter set. Poseidon-5 only.
"""


def emit_h():
    out = ["/*", " * zkn_poseidon_opt_tables.h — Poseidon tables, Montgomery form.", " *"]
    out += NOTE.rstrip("\n").split("\n")
    out += [" */",
            "#ifndef ZKN_POSEIDON_OPT_TABLES_H",
            "#define ZKN_POSEIDON_OPT_TABLES_H",
            "",
            "#include <stdint.h>",
            '#include "zkn_config.h"',
            "",
            "/* Arities compiled in, one mask per field: bit n set = Poseidon-n",
            " * (n inputs, t = n + 1). A build that needs fewer can pass, e.g.,",
            " * -DZKN_POSEIDON_ARITIES=0x24 (Poseidon-2 and Poseidon-5 over BN254) or",
            " * -DZKN_POSEIDON_BLS12381_ARITIES=0 (no Bandersnatch) and save the flash",
            " * of the others; zkn_poseidon_init then refuses them. */"]
    for name, _, ts, macro in INSTANCES:
        out += [f"#ifndef {macro}",
                f"#define {macro} 0x{mask_of(ts):02X}u",
                "#endif",
                f"#if ({macro}) & ~0x{mask_of(ts):02X}u",
                f"#error \"{macro}: no table generated for this arity, see INSTANCES in tools/gen_poseidon_opt.py\"",
                "#endif"]
    out += [""]
    for name, _, ts, macro in INSTANCES:
        for t in ts:
            k = sparse_rounds(name, t)
            n = table_len(t, k)
            out.append(f"/* {name:8s} Poseidon-{t - 1} (t = {t}, RP = {RP[t]}), {k:2d} sparse rounds: "
                       f"{n:4d} elements, {n * 32:5d} bytes */")
    out += ["",
            "/* A field element of the tables: 8 little-endian 32-bit limbs. */",
            "typedef uint32_t zkn_poseidon_fe_t[8];",
            "",
            "/* Table of (field, arity) for the modulus `n` (8 limbs, as in the",
            " * Montgomery context) and `nb_inputs` inputs, or NULL when that pair has",
            " * no table compiled in. *sparse_rounds receives k, the number of partial",
            " * rounds, counted from the last, that use the sparse matrices. */",
            "const zkn_poseidon_fe_t *zkn_poseidon_opt_table(const uint32_t *n,",
            "                                               unsigned nb_inputs,",
            "                                               unsigned *sparse_rounds);",
            "",
            "#endif /* ZKN_POSEIDON_OPT_TABLES_H */", ""]
    return "\n".join(out)


def emit_c(tables):
    out = ["/*", " * zkn_poseidon_opt_tables.c — Poseidon tables, Montgomery form.", " *"]
    out += NOTE.rstrip("\n").split("\n")
    out += [" *",
            " * SW backend only, like zkn_poseidon_soft.c: the Montgomery radix is the",
            " * one of zkn_mont256 (R = 2^256).",
            " */",
            "#ifndef ZKN_BN_BACKEND_LEDGER",
            "",
            "#include <string.h>",
            '#include "zkn_poseidon_opt_tables.h"',
            ""]
    for name, q, ts, macro in INSTANCES:
        for t in ts:
            k = sparse_rounds(name, t)
            flat = layout(t, k, tables[name][t])
            n_c = t * RF + RP[t]
            marks = {0: "C", n_c: "MT"}
            if k:
                marks[n_c + t * t] = "PT"
                marks[n_c + 2 * t * t] = "S"
            out += [f"#if (({macro}) >> {t - 1}) & 1u",
                    f"static const uint32_t POSEIDON_{name}_T{t}[{len(flat)}][8] = {{"]
            for i, x in enumerate(flat):
                if i in marks:
                    out.append(f"    /* {marks[i]} */")
                out.append("    {" + limbs(x, q) + "},")
            out += ["};", "#endif", ""]
    for name, q, ts, macro in INSTANCES:
        out += [f"#if {macro}",
                f"static const uint32_t POSEIDON_{name}_MODULUS[8] = {{",
                "    " + limbs(q, q, montgomery=False),
                "};",
                "#endif",
                ""]
    out += ["const zkn_poseidon_fe_t *zkn_poseidon_opt_table(const uint32_t *n,",
            "                                               unsigned nb_inputs,",
            "                                               unsigned *sparse_rounds)",
            "{"]
    for name, q, ts, macro in INSTANCES:
        out += [f"#if {macro}",
                f"    if (memcmp(n, POSEIDON_{name}_MODULUS, sizeof(POSEIDON_{name}_MODULUS)) == 0) {{",
                "        switch (nb_inputs) {"]
        for t in ts:
            out += [f"#if (({macro}) >> {t - 1}) & 1u",
                    f"        case {t - 1}: *sparse_rounds = {sparse_rounds(name, t)}; return POSEIDON_{name}_T{t};",
                    "#endif"]
        out += ["        default: return NULL;",
                "        }",
                "    }",
                "#endif"]
    out += ["    (void)n;",
            "    (void)nb_inputs;",
            "    (void)sparse_rounds;",
            "    return NULL;",
            "}",
            "",
            "#endif /* !ZKN_BN_BACKEND_LEDGER */", ""]
    return "\n".join(out)


def check_against_circomlibjs(directory, tables):
    def load(name):
        with open(os.path.join(directory, name)) as f:
            return json.load(f)

    def ints(o):
        return [ints(x) for x in o] if isinstance(o, list) else int(o, 16)

    ref = load("poseidon_constants.json")
    opt = load("poseidon_constants_opt.json")
    for t in INSTANCES[0][2]:
        c, m = reference_constants(t)
        oc, os_, om, op = tables["BN254"][t]
        k = t - 2
        what = "C, M and pushed C"
        assert c == ints(ref["C"][k]), f"t={t}: round constants differ"
        assert m == ints(ref["M"][k]), f"t={t}: MDS matrix differs"
        assert oc == ints(opt["C"][k]), f"t={t}: pushed constants differ"
        assert om == ints(opt["M"][k]), f"t={t}: transposed M differs"
        if sparse_rounds("BN254", t) == RP[t]:
            assert [x for row in os_ for x in row] == ints(opt["S"][k]), f"t={t}: S differs"
            assert op == ints(opt["P"][k]), f"t={t}: P differs"
            what += ", S, P"
        print(f"t={t}: {what} identical to circomlibjs", file=sys.stderr)


def kat_inputs(t, q, large):
    return [q - 1 - i for i in range(t - 1)] if large else [i + 1 for i in range(t - 1)]


def main(argv):
    if "--sparse" in argv:
        parse_sparse(argv[argv.index("--sparse") + 1])

    tables = {}
    for name, q, ts, _ in INSTANCES:
        tables[name] = {}
        for t in ts:
            k = sparse_rounds(name, t)
            tables[name][t] = optimized_constants(t, q, k)
            # The permutation read from the table must equal the reference one.
            flat = layout(t, k, tables[name][t])
            for large in (False, True):
                for init, nout in ((0, 1), (7, t)):
                    x = kat_inputs(t, q, large)
                    assert (poseidon_reference(t, x, q, init, nout)
                            == poseidon_from_table(t, k, flat, q, x, init, nout)), (name, t)

    if "--check" in argv:
        check_against_circomlibjs(argv[argv.index("--check") + 1], tables)

    if "--kat" in argv:
        for name, q, ts, _ in INSTANCES:
            for t in ts:
                for large in (False, True):
                    for init, nout in ((0, 1), (7, t)):
                        out = poseidon_reference(t, kat_inputs(t, q, large), q, init, nout)
                        print(name, t - 1, int(large), init, nout, " ".join(f"{v:064x}" for v in out))
        return

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dst = os.path.join(root, "src", "zkn_mont")
    if "--out" in argv:
        dst = argv[argv.index("--out") + 1]
    with open(os.path.join(dst, "zkn_poseidon_opt_tables.h"), "w") as f:
        f.write(emit_h())
    with open(os.path.join(dst, "zkn_poseidon_opt_tables.c"), "w") as f:
        f.write(emit_c(tables))
    for name, _, ts, _ in INSTANCES:
        n = sum(table_len(t, sparse_rounds(name, t)) for t in ts)
        ks = ", ".join(f"{t - 1}:{sparse_rounds(name, t)}" for t in ts)
        print(f"{name}: {n} elements, {n * 32} bytes (sparse rounds per arity: {ks})", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
