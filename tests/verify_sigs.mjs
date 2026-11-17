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

/* msg_rev read little-endian is >= p: the signer must refuse it (M-4) and
 * test_sign_host then writes an all-zero sigB. */
const isZero = (h) => /^0*$/.test(h);
const okB = isZero(data.sigB.r8x) && isZero(data.sigB.r8y) && isZero(data.sigB.s);
console.log(`\n── sigB (msg_rev >= p) ──\n   ${okB ? "✅ refused by the signer" : "❌ was signed"}`);

console.log("\n════════════════════════════════════════════════════════════");
if (okA && okB) {
  console.log("  ✅ sigA verifies against circomlibjs and sigB (msg >= p) was refused");
  process.exit(0);
} else {
  console.log("  ❌ sigA failed verification or sigB was not refused");
  process.exit(1);
}
