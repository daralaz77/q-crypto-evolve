// X25519, HKDF y fuzzing de la capa AEAD.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, diffieHellman, hkdfSync, createHmac, randomBytes } from 'node:crypto';
import { x25519 } from './support/x25519-ref.mjs';
import { gcm } from './support/gcm-ref.mjs';
import { encrypt, decrypt } from '../src/aead.mjs';
const H = (x) => Buffer.from(x, 'hex');
const nodeX = (priv, pub) => diffieHellman({
  privateKey: createPrivateKey({ key: Buffer.concat([H('302e020100300506032b656e04220420'), priv]), format: 'der', type: 'pkcs8' }),
  publicKey: createPublicKey({ key: Buffer.concat([H('302a300506032b656e032100'), pub]), format: 'der', type: 'spki' }) });

test('X25519 RFC 7748 §6.1 (Alice/Bob): Node y oráculo', () => {
  const a = H('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), b = H('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const base = Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]);
  const pa = x25519(a, base), pb = x25519(b, base), K = H('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
  assert.equal(pa.toString('hex'), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  assert.equal(pb.toString('hex'), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  assert.deepEqual(x25519(a, pb), K); assert.deepEqual(nodeX(a, pb), K); assert.deepEqual(nodeX(b, pa), K);
});
test('X25519: diferencial Node↔oráculo en 200 pares aleatorios + RFC 7748 iterado (1 y 1000)', () => {
  for (let i = 0; i < 200; i++) { const a = randomBytes(32), b = randomBytes(32); const pb = x25519(b, Buffer.concat([Buffer.from([9]), Buffer.alloc(31)])); assert.deepEqual(nodeX(a, pb), x25519(a, pb)); }
  let k = Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]), u = Buffer.from(k);
  for (let i = 1; i <= 1000; i++) { const nk = x25519(k, u); u = k; k = nk; if (i === 1) assert.equal(k.toString('hex'), '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'); }
  assert.equal(k.toString('hex'), '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51');
});
test('X25519: punto de bajo orden produce secreto todo ceros (el híbrido debe rechazarlo)', () => {
  const zero = Buffer.alloc(32); const a = randomBytes(32);
  assert.deepEqual(x25519(a, zero), zero);
  assert.throws(() => nodeX(a, zero), 'node debe rechazar u=0');
});
test('HKDF-SHA256 RFC 5869 caso 1', () => {
  const okm = Buffer.from(hkdfSync('sha256', Buffer.alloc(22, 0x0b), H('000102030405060708090a0b0c'), H('f0f1f2f3f4f5f6f7f8f9'), 42));
  assert.equal(okm.toString('hex'), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});
test('interop: AES-256-GCM de mi módulo se descifra con el oráculo GCM independiente', () => {
  for (let i = 0; i < 50; i++) { const key = randomBytes(32), pt = randomBytes(i * 7), aad = randomBytes(i);
    const blob = encrypt('aes-256-gcm', key, pt, aad);
    const out = gcm(key, blob.subarray(2, 14), aad, blob.subarray(14, blob.length - 16), 'dec', 16, blob.subarray(blob.length - 16));
    assert.ok(out && out.equals(pt)); }
});
for (const alg of ['aes-256-gcm', 'chacha20-poly1305']) test(`fuzz ${alg}: 20000 mutaciones (flip, truncar, extender, empalmar) nunca se aceptan`, () => {
  const key = randomBytes(32); let n = 0;
  for (let i = 0; i < 2000; i++) {
    const aad = randomBytes(i % 20), blob = encrypt(alg, key, randomBytes(i % 90), aad);
    for (let j = 0; j < 10; j++) {
      let m = Buffer.from(blob); const r = randomBytes(3), kind = r[0] % 4;
      if (kind === 0) m[r[1] % m.length] ^= 1 << (r[2] % 8);
      else if (kind === 1) m = m.subarray(0, r[1] % m.length);
      else if (kind === 2) m = Buffer.concat([m, randomBytes(1 + (r[1] % 8))]);
      else m = Buffer.concat([m.subarray(0, 14), randomBytes(m.length - 14)]);
      if (m.equals(blob)) continue;
      assert.throws(() => decrypt(key, m, aad), `mutación aceptada (kind ${kind})`); n++;
    }
  }
  assert.ok(n > 15000);
});
test('fuzz: entradas aleatorias arbitrarias solo lanzan Error (sin cuelgues ni otros tipos)', () => {
  const key = randomBytes(32);
  for (let i = 0; i < 20000; i++) { try { decrypt(key, randomBytes(i % 120)); assert.fail('aceptó ruido'); } catch (e) { assert.ok(e instanceof Error && e.name !== 'AssertionError', String(e)); } }
});
