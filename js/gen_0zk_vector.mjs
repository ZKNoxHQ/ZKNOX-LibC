// Build a deterministic RAILGUN 0zk address and emit C-ready hex
// for tests/test_bech32m_host.c.
//
// Payload layout (73 bytes):
//   [0]      version          = 0x01
//   [1..32]  masterPublicKey  = 0x00, 0x01, ..., 0x1F  (32 bytes)
//   [33..40] networkXOR       = 0xAA repeated (8 bytes)
//   [41..72] viewingPublicKey = 0xC0, 0xC1, ..., 0xDF  (32 bytes)
import { bech32m } from "@scure/base";

const payload = new Uint8Array(73);
payload[0] = 0x01;
for (let i = 0; i < 32; i++) payload[1 + i] = i;             // mpk
for (let i = 0; i < 8;  i++) payload[33 + i] = 0xaa;         // networkXOR
for (let i = 0; i < 32; i++) payload[41 + i] = 0xc0 + i;     // vpub

const addr = bech32m.encode("0zk", bech32m.toWords(payload), 127);
console.log(`length: ${addr.length}`);
console.log(`address: ${addr}`);

const hex = Buffer.from(payload).toString("hex");
console.log(`mpk hex: ${hex.slice(2, 2 + 64)}`);
console.log(`payload hex: ${hex}`);
