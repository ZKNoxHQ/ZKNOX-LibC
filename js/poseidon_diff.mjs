// Differential test of the library's Poseidon against circomlibjs, on random
// vectors drawn from the OS CSPRNG (node:crypto).
//
//   make poseidon-diff            (builds bin/poseidon_cli, then runs this)
//   node js/poseidon_diff.mjs [--count 10000] [--cli bin/poseidon_cli]
//
// BN254, Poseidon-1 .. Poseidon-7:
//   * `count` vectors uniform in [0, p), initState 0, one output, compared
//     with circomlibjs buildPoseidon (wasm) and buildPoseidonReference;
//   * count / 10 vectors of raw 256-bit inputs (reduced mod p by the
//     library), a random initState and all t outputs, plus a few edge
//     vectors, compared with buildPoseidonReference.
// BLS12-381 Fr, Poseidon-5 (what EdDSA / FROST compute on Bandersnatch):
//   * the same two batches, compared with the reference rounds evaluated in
//     BigInt over that field with the circomlibjs constants (circomlibjs
//     itself is BN254 only). That BigInt reference is first checked against
//     circomlibjs over BN254.
//
// Exit status 0 only if every output is identical.
import { buildPoseidon, buildPoseidonReference } from "circomlibjs";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, dflt) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : dflt;
};
const COUNT = parseInt(opt("--count", "10000"), 10);
const CLI = opt("--cli", join(here, "..", "bin", "poseidon_cli"));

const P_BN254 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const P_BLS12381 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const RF = 8;
const RP = [56, 57, 56, 60, 60, 63, 64];

// ── Random values ────────────────────────────────────────────────────
const toBig = (buf) => BigInt("0x" + buf.toString("hex"));
const random256 = () => toBig(randomBytes(32));
function randomBelow(q) {
    const bits = q.toString(2).length;
    for (;;) {
        const v = random256() >> BigInt(256 - bits);
        if (v < q) return v;
    }
}

// ── Reference rounds in BigInt, circomlibjs constants, any modulus ───
const constants = JSON.parse(readFileSync(
    join(here, "node_modules", "circomlibjs", "src", "poseidon_constants.json"), "utf8"));
const C = constants.C.map((row) => row.map(BigInt));
const M = constants.M.map((m) => m.map((row) => row.map(BigInt)));

function referenceBig(q, inputs, init, nOut) {
    const t = inputs.length + 1;
    const c = C[t - 2], m = M[t - 2], rp = RP[t - 2];
    const pow5 = (a) => { const a2 = a * a % q; return a2 * a2 % q * a % q; };
    let st = [BigInt(init) % q, ...inputs.map((a) => a % q)];
    for (let r = 0; r < RF + rp; r++) {
        st = st.map((a, i) => (a + c[r * t + i]) % q);
        if (r < RF / 2 || r >= RF / 2 + rp) st = st.map(pow5);
        else st[0] = pow5(st[0]);
        st = st.map((_, i) => st.reduce((acc, a, j) => (acc + m[i][j] * a) % q, 0n));
    }
    return st.slice(0, nOut);
}

// ── Library, through tests/poseidon_cli.c ────────────────────────────
function library(field, n, nOut, vectors) {
    const rec = 4 + 32 * n;
    const input = Buffer.alloc(rec * vectors.length);
    vectors.forEach((v, k) => {
        input.writeUInt32BE(v.init, k * rec);
        v.inputs.forEach((x, i) =>
            input.write(x.toString(16).padStart(64, "0"), k * rec + 4 + 32 * i, "hex"));
    });
    const r = spawnSync(CLI, [field, String(n), String(nOut)],
        { input, maxBuffer: 1 << 28 });
    if (r.status !== 0 || r.stdout.length !== 32 * nOut * vectors.length) {
        throw new Error(`${CLI} ${field} ${n} ${nOut}: status ${r.status} ${r.stderr}`);
    }
    return vectors.map((_, k) => Array.from({ length: nOut }, (_, o) =>
        toBig(r.stdout.subarray(32 * (k * nOut + o), 32 * (k * nOut + o + 1)))));
}

const edges = (q, n) => [0n, 1n, q - 1n, q, q + 1n, (1n << 256n) - 1n]
    .map((x) => ({ init: 0, inputs: Array(n).fill(x) }));

function compare(label, got, want) {
    let bad = 0;
    got.forEach((g, k) => {
        if (g.length !== want[k].length || g.some((x, i) => x !== want[k][i])) bad++;
    });
    const n = got.length;
    console.log(`  ${label.padEnd(58)} ${n - bad}/${n}${bad ? "  MISMATCH" : ""}`);
    return bad;
}

// ── Run ──────────────────────────────────────────────────────────────
const wasm = await buildPoseidon();
const ref = await buildPoseidonReference();
const F = ref.F;
const asList = (o, nOut) => (nOut === 1 ? [o] : o);
const circomWasm = (v, nOut) =>
    asList(wasm(v.inputs, v.init, nOut), nOut).map((x) => wasm.F.toObject(x));
const circomRef = (v, nOut) =>
    asList(ref(v.inputs, v.init, nOut), nOut).map((x) => F.toObject(x));

let failures = 0;
console.log(`BN254 (circomlib), ${COUNT} random vectors per arity`);
for (let n = 1; n <= 7; n++) {
    const t = n + 1;
    const hash = Array.from({ length: COUNT }, () =>
        ({ init: 0, inputs: Array.from({ length: n }, () => randomBelow(P_BN254)) }));
    const got = library("bn254", n, 1, hash);
    failures += compare(`Poseidon-${n}  vs circomlibjs wasm`, got, hash.map((v) => circomWasm(v, 1)));
    failures += compare(`Poseidon-${n}  vs circomlibjs reference`, got, hash.map((v) => circomRef(v, 1)));

    const full = Array.from({ length: Math.ceil(COUNT / 10) }, () =>
        ({ init: randomBytes(4).readUInt32BE(0), inputs: Array.from({ length: n }, random256) }))
        .concat(edges(P_BN254, n));
    const reduced = full.map((v) => ({ init: v.init, inputs: v.inputs.map((x) => x % P_BN254) }));
    failures += compare(`Poseidon-${n}  initState, ${t} outputs, inputs >= p`,
        library("bn254", n, t, full), reduced.map((v) => circomRef(v, t)));

    // The BigInt reference used below for BLS12-381 is the circomlibjs one.
    const some = hash.slice(0, 50);
    failures += compare(`Poseidon-${n}  BigInt reference vs circomlibjs`,
        some.map((v) => referenceBig(P_BN254, v.inputs, 0, 1)), some.map((v) => circomRef(v, 1)));
}

console.log(`BLS12-381 Fr (Bandersnatch), same parameter set, ${COUNT} random vectors`);
{
    const n = 5, t = 6, q = P_BLS12381;
    const hash = Array.from({ length: COUNT }, () =>
        ({ init: 0, inputs: Array.from({ length: n }, () => randomBelow(q)) }));
    failures += compare(`Poseidon-${n}  vs BigInt reference`,
        library("bls12381", n, 1, hash), hash.map((v) => referenceBig(q, v.inputs, 0, 1)));
    const full = Array.from({ length: Math.ceil(COUNT / 10) }, () =>
        ({ init: randomBytes(4).readUInt32BE(0), inputs: Array.from({ length: n }, random256) }))
        .concat(edges(q, n));
    failures += compare(`Poseidon-${n}  initState, ${t} outputs, inputs >= q`,
        library("bls12381", n, t, full), full.map((v) => referenceBig(q, v.inputs, v.init, t)));
}

console.log(failures ? `FAILED: ${failures} mismatching vectors` : "ALL IDENTICAL");
process.exit(failures ? 1 : 0);
