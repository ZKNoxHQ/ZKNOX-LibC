/* Verify the signatures produced by test_sign_full against circomlibjs.
 * Reads signatures.json and tries multiple message encodings. */

import { buildEddsa } from "circomlibjs";
import * as fs from "fs";

const data = JSON.parse(fs.readFileSync("signatures.json", "utf8"));

const hex2buf = (h) => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b,16)));
const reverse = (b) => new Uint8Array(Array.from(b).reverse());

const eddsa = await buildEddsa();
const F = eddsa.babyJub.F;

const priv = hex2buf(data.priv);
const pub = eddsa.prv2pub(priv);
const msgAsIs = hex2buf(data.msg_asIs);
const msgRev  = hex2buf(data.msg_rev);

function importSig(s) {
  const r8xLE = reverse(hex2buf(s.r8x));
  const r8yLE = reverse(hex2buf(s.r8y));
  return {
    R8: [F.toMontgomery(r8xLE), F.toMontgomery(r8yLE)],
    S:  BigInt("0x" + s.s),
  };
}

const sigA = importSig(data.sigA);
const sigB = importSig(data.sigB);

const tries = [
  ["msg_asIs",                msgAsIs,                                ],
  ["F.toMontgomery(msg_asIs)", F.toMontgomery(msgAsIs)                ],
  ["msg_rev",                 msgRev                                  ],
  ["F.toMontgomery(msg_rev)", F.toMontgomery(msgRev)                  ],
];

let allOk = true;

function testSig(label, sig) {
  console.log(`\n── ${label} ──`);
  let found = false;
  for (const [name, m] of tries) {
    const ok = eddsa.verifyPoseidon(m, sig, pub);
    console.log(`   ${name.padEnd(28)} : verify = ${ok ? "✅ VALID" : "❌ invalid"}`);
    if (ok) found = true;
  }
  if (!found) {
    console.log(`   ⚠️  No msg encoding makes this sig valid against circomlibjs`);
    allOk = false;
  }
  return found;
}

const okA = testSig("sigA (host signed msg_asIs)", sigA);
const okB = testSig("sigB (host signed msg_rev)",  sigB);

console.log("\n════════════════════════════════════════════════════════════");
if (okA && okB) {
  console.log("  ✅ Both host signatures verify successfully against circomlibjs");
  console.log("     (with a specific msg encoding convention)");
  process.exit(0);
} else {
  console.log("  ❌ At least one sig failed all verification attempts");
  process.exit(1);
}
