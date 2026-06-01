// Print circomlibjs Poseidon(1..k) for k=1..7, inputs [1, 2, ..., k].
// Used to generate known-answer vectors for tests/test_poseidon_soft.c.
import { buildPoseidonOpt } from "circomlibjs";

const poseidon = await buildPoseidonOpt();
const F = poseidon.F;

for (let n = 1; n <= 7; n++) {
    const inputs = Array.from({ length: n }, (_, i) => BigInt(i + 1));
    const out = F.toObject(poseidon(inputs)).toString(16).padStart(64, "0");
    console.log(`P${n}(${inputs.join(",")}) = 0x${out}`);
}
