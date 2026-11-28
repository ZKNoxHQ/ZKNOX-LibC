#!/usr/bin/env python3
"""
gen_poseidon_opt.py — generates the Poseidon tables of the SW backend:
    src/zkn_mont/zkn_poseidon_opt_tables.h
    src/zkn_mont/zkn_poseidon_opt_tables.c

Parameter sets: Poseidon with the x^5 S-box and RF = 8, as hadeshash
generate_parameters_grain.sage defines them for a prime field. One instance
per field: the Grain LFSR is seeded with the bit length of the field (254
for BN254, 255 for BLS12-381), t, RF and RP.

Everything is derived from the parameters, with no input file:
  1. round constants and MDS matrix from the Grain LFSR (Poseidon paper,
     hadeshash generate_parameters_grain.sage), the matrix being the first
     one that passes the three checks of that script;
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
  BN254     254/t/8/RP, the circomlib instance, t = 2..8 (Poseidon-1 ..
            Poseidon-7);
  BLS12381  255/6/8/60, the instance of the BLS12-381 scalar field for
            t = 6 (Poseidon-5): what EdDSA and FROST hash with on
            Bandersnatch, whose base field that is. Same rules as the
            255/3/8/57 and 255/5/8/60 parameter files of hadeshash, and the
            instance ZKNOX-Poseidons generates for this field and this t.
            Until this version the table held the BN254 integers evaluated
            over the BLS12-381 field.
Constants, matrices, pushed constants and sparse matrices depend on the
field, hence one table per (field, arity).

Usage, from the repository root:
  python3 tools/gen_poseidon_opt.py              rewrites the two files
  python3 tools/gen_poseidon_opt.py --check DIR  also compares the BN254
        tables with DIR/poseidon_constants.json and
        DIR/poseidon_constants_opt.json (js/node_modules/circomlibjs/src)
  python3 tools/gen_poseidon_opt.py --kat        prints known answers
        (reference permutation) for tests/test_poseidon_opt.c
  python3 tools/gen_poseidon_opt.py --cx-matrix BLS12381:5
        prints the MDS matrix of an instance as the array the cx backend
        reads (hash/zkn_poseidon_constants.c): 32 bytes big endian per
        coefficient, row by row, not in Montgomery form
  --out DIR writes the two files to DIR instead of src/zkn_mont.
After a change of --sparse, run `make test` and `make poseidon-diff`.

Python 3, standard library only.
"""
import json
import os
import sys

P_BN254 = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
P_BLS12381 = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

RF = 8
# Partial rounds for a 254-bit and for a 255-bit field (Poseidon paper,
# 128 bits of security with the margin): the same numbers.
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
    def __init__(self, n_bits, t, rp):
        bits = []

        def push(value, width):
            bits.extend((value >> i) & 1 for i in range(width - 1, -1, -1))

        push(1, 2)        # field: GF(p)
        push(0, 4)        # S-box: x^alpha
        push(n_bits, 12)  # bit length of the field
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


def reference_constants(q, t):
    """Round constants C[(RF+RP)*t] and MDS matrix M[t][t] of the instance
    of GF(q): what generate_parameters_grain.sage prints for
    (1, 0, bits(q), t, RF, RP, q). For BN254 that is the content of
    circomlibjs poseidon_constants.json."""
    if (q, t) in _REFERENCE:
        return _REFERENCE[(q, t)]
    n_bits = q.bit_length()
    rp = RP[t]
    g = Grain(n_bits, t, rp)
    c = []
    while len(c) < (RF + rp) * t:
        v = g.integer(n_bits)
        if v < q:
            c.append(v)
    # Cauchy matrix M[i][j] = 1 / (x_i + y_j), x and y drawn from the stream.
    # The script draws again on a duplicate, on x_i + y_j = 0, and when one
    # of its three checks refuses the matrix.
    while True:
        r = [g.integer(n_bits) % q for _ in range(2 * t)]
        if len(set(r)) != 2 * t:
            continue
        xs, ys = r[:t], r[t:]
        if any((x + y) % q == 0 for x in xs for y in ys):
            continue
        m = [[pow(x + y, q - 2, q) for y in ys] for x in xs]
        if matrix_is_secure(m, q):
            break
    _REFERENCE[(q, t)] = (c, m)
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


# ── The three matrix checks of generate_parameters_grain.sage (s = 1) ──
def _rref(rows, q):
    m = [list(r) for r in rows]
    piv = []
    r = 0
    for col in range(len(m[0]) if m else 0):
        k = next((i for i in range(r, len(m)) if m[i][col] % q), None)
        if k is None:
            continue
        m[r], m[k] = m[k], m[r]
        inv = pow(m[r][col], q - 2, q)
        m[r] = [x * inv % q for x in m[r]]
        for i in range(len(m)):
            if i != r and m[i][col]:
                f = m[i][col]
                m[i] = [(x - f * y) % q for x, y in zip(m[i], m[r])]
        piv.append(col)
        r += 1
    return m[:r], piv


def _rank(rows, q):
    return len(_rref(rows, q)[1]) if rows else 0


def _kernel(rows, n, q):
    """Basis of the vectors v of GF(q)^n with rows . v = 0."""
    m, piv = _rref(rows, q)
    basis = []
    for f in (col for col in range(n) if col not in piv):
        v = [0] * n
        v[f] = 1
        for r, col in enumerate(piv):
            v[col] = (-m[r][f]) % q
        basis.append(v)
    return basis


def _mat_pow(a, e, q):
    n = len(a)
    r = [[int(i == j) for j in range(n)] for i in range(n)]
    while e:
        if e & 1:
            r = mat_mul(r, a, q)
        a = mat_mul(a, a, q)
        e >>= 1
    return r


def _poly_mod(a, f, q):
    a = list(a)
    inv = pow(f[-1], q - 2, q)
    while len(a) >= len(f):
        c = a[-1] * inv % q
        if c:
            off = len(a) - len(f)
            for i, y in enumerate(f):
                a[off + i] = (a[off + i] - c * y) % q
        a.pop()
    while a and a[-1] == 0:
        a.pop()
    return a


def _poly_mulmod(a, b, f, q):
    if not a or not b:
        return []
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            r[i + j] = (r[i + j] + x * y) % q
    return _poly_mod(r, f, q)


def _poly_powmod(base, e, f, q):
    r = [1]
    base = _poly_mod(base, f, q)
    while e:
        if e & 1:
            r = _poly_mulmod(r, base, f, q)
        base = _poly_mulmod(base, base, f, q)
        e >>= 1
    return r


def _poly_gcd(a, b, q):
    a, b = list(a), list(b)
    while b:
        a, b = b, _poly_mod(a, b, q)
    inv = pow(a[-1], q - 2, q) if a else 0
    return [x * inv % q for x in a]


def _char_poly(a, q):
    """det(xI - a), coefficients from the constant term up (Faddeev-LeVerrier)."""
    n = len(a)
    c = [0] * n + [1]
    m = [[0] * n for _ in range(n)]
    for k in range(1, n + 1):
        m = [[(sum(a[i][x] * m[x][j] for x in range(n)) + (c[n - k + 1] if i == j else 0)) % q
              for j in range(n)] for i in range(n)]
        am = mat_mul(a, m, q)
        c[n - k] = (-sum(am[i][i] for i in range(n)) * pow(k, q - 2, q)) % q
    return c


def _roots(f, q):
    """Roots in GF(q) of f: gcd with x^q - x, then equal-degree splitting."""
    xq = _poly_powmod([0, 1], q, f, q)
    xq += [0] * (2 - len(xq))
    xq[1] = (xq[1] - 1) % q
    while xq and xq[-1] == 0:
        xq.pop()
    found = []
    stack = [_poly_gcd(f, xq, q) if xq else list(f)]
    shift = 0
    while stack:
        h = stack.pop()
        if len(h) <= 1:
            continue
        if len(h) == 2:
            found.append((-h[0] * pow(h[1], q - 2, q)) % q)
            continue
        while True:
            shift += 1                      # deterministic: x + 1, x + 2, ...
            w = _poly_powmod([shift, 1], (q - 1) // 2, h, q)
            w += [0] * (1 - len(w))
            w[0] = (w[0] - 1) % q
            while w and w[-1] == 0:
                w.pop()
            d = _poly_gcd(h, w, q) if w else []
            if 1 < len(d) < len(h):
                rest, rem = list(h), []
                quo = [0] * (len(h) - len(d) + 1)
                for i in range(len(quo) - 1, -1, -1):
                    quo[i] = rest[i + len(d) - 1]
                    for j, y in enumerate(d):
                        rest[i + j] = (rest[i + j] - quo[i] * y) % q
                assert not any(rest[:len(d) - 1]), rem
                stack += [d, quo]
                break
    return found


def _algorithm_1(m, q):
    t = len(m)
    powers = [_mat_pow(m, j + 1, q) for j in range(t + 1)]
    for i in range(1, t):
        mi = powers[i - 1]
        if all(mi[a][b] == (mi[0][0] if a == b else 0) for a in range(t) for b in range(t)):
            return False
        # S: x_0 = 0 and (M^k x)_0 = 0 for k = 1 .. i - 1
        cons = [[1] + [0] * (t - 1)] + [[0] + powers[k][0][1:] for k in range(i - 1)]
        s_basis = _kernel(cons, t, q)
        inter = []
        for lam in _roots(_char_poly(mi, q), q):
            shifted = [[(mi[a][b] - (lam if a == b else 0)) % q for b in range(t)] for a in range(t)]
            inter += _kernel(shifted + cons, t, q)
        if 1 <= _rank(inter, q) < t:
            return False
        for j in range(1, i + 1):
            image = [mat_mul_vec(powers[j - 1], v, q) for v in s_basis]
            if s_basis and all(not any(mat_mul_vec(cons, v, q)) for v in image):
                return False
    return True


def _algorithm_2(m, q):
    """The first unit vector generates the whole space under m."""
    t = len(m)
    v = [1] + [0] * (t - 1)
    span = [v]
    while True:
        before = _rank(span, q)
        v = mat_mul_vec(m, v, q)
        span.append(v)
        after = _rank(span, q)
        if after == t:
            return True
        if after <= before:
            return False


def matrix_is_secure(m, q):
    """algorithm_1, algorithm_2 and algorithm_3 of the script: no invariant
    subspace trail through the partial rounds."""
    return (_algorithm_1(m, q) and _algorithm_2(m, q)
            and all(_algorithm_2(_mat_pow(m, r, q), q) for r in range(2, 4 * len(m) + 1)))


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
    """(C, S, M, P) over GF(q). For BN254, C and M are those of circomlibjs
    poseidon_constants_opt.json; S (k rows of 2t - 1) and P are too when
    k = RP."""
    c, m = reference_constants(q, t)
    om = transpose(m)
    p, s = calculate_ps(t, om, q, k)
    return convert_constants(t, c, om, q), s, om, p


# ── The two permutations, used to check one against the other ─────────
def poseidon_reference(t, inputs, q, init=0, nout=1):
    c, m = reference_constants(q, t)
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
 * Poseidon tables of the SW backend (x^5, RF = 8, constants and MDS matrix
 * from the Grain LFSR, one instance per field as hadeshash defines them).
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
 *     BN254     254/t/8/RP, the circomlib instance, Poseidon-1 .. Poseidon-7.
 *     BLS12381  255/6/8/60, the instance of the BLS12-381 scalar field:
 *               what EdDSA / FROST hash with on Bandersnatch. Poseidon-5
 *               only.
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
        c, m = reference_constants(P_BN254, t)
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

    if "--cx-matrix" in argv:
        name, n = argv[argv.index("--cx-matrix") + 1].split(":")
        q = next(i[1] for i in INSTANCES if i[0] == name)
        t = int(n) + 1
        _, m = reference_constants(q, t)
        print(f"/* {name} Poseidon-{t - 1} (t = {t}): MDS matrix, {t * t} coefficients of 32 bytes,")
        print(" * big endian, row by row. tools/gen_poseidon_opt.py --cx-matrix "
              f"{name}:{t - 1} */")
        for row in m:
            for x in row:
                b = x.to_bytes(32, "big")
                for off in (0, 16):
                    print("    " + " ".join(f"0x{v:02x}," for v in b[off:off + 16]))
        return

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
