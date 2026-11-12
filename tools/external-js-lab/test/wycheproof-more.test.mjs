// Wycheproof: ML-KEM-512/768/1024 (4 suites cada una) y X25519.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, encapsulate, decapsulate, diffieHellman } from 'node:crypto';
import * as R from './support/mlkem-ref.mjs';
import { x25519 } from './support/x25519-ref.mjs';

const load = (f) => JSON.parse(readFileSync(new URL(`../vectors/${f}`, import.meta.url)));
const H = (x) => Buffer.from(x, 'hex');
const stats = {}; test.after(() => console.log('# RESUMEN WYCHEPROOF+', JSON.stringify(stats)));
const note = (k, r) => { ((stats[k] ??= {})[r] = (stats[k][r] ?? 0) + 1); };
const OID = { 'ml-kem-512': '01', 'ml-kem-768': '02', 'ml-kem-1024': '03' };
const lenEnc = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (t, b) => Buffer.concat([Buffer.from([t]), lenEnc(b.length), b]);
const fromDk = (set, dk) => createPrivateKey({ key: tlv(0x30, Buffer.concat([H('020100'), tlv(0x30, H('06096086480165030404' + OID[set])), tlv(4, tlv(4, dk))])), format: 'der', type: 'pkcs8' });
const fromSeed = (set, s) => createPrivateKey({ key: s, format: 'raw-seed', asymmetricKeyType: set });
const pubFromEk = (set, ek) => createPublicKey({ key: ek, format: 'raw-public', asymmetricKeyType: set });
const tryOr = (f) => { try { return f(); } catch { return null; } };
const tests = (f) => load(f).testGroups.flatMap((g) => g.tests);

for (const set of Object.keys(R.PARAMS)) {
  const n = set.replace('ml-kem-', '');
  test(`Wycheproof ${set} test: semilla→ek, decapsulación, rechazo implícito`, () => {
    const fails = [];
    for (const t of tests(`mlkem_${n}_test.json`)) {
      const sk = tryOr(() => fromSeed(set, H(t.seed)));
      if (!sk) { if (t.result !== 'invalid') fails.push(`${t.tcId} semilla válida rechazada`); note(set + ' test', 'invalid(semilla)'); continue; }
      if (!createPublicKey(sk).export({ format: 'raw-public' }).equals(H(t.ek))) fails.push(`${t.tcId} ek`);
      const K = tryOr(() => decapsulate(sk, H(t.c)));
      if (t.result === 'valid' && !(K && K.equals(H(t.K)))) fails.push(`${t.tcId} K`);
      if (t.result === 'invalid' && K && K.equals(H(t.K))) fails.push(`${t.tcId} invalid acepta`);
      const dk = R.keyGenInternal(set, H(t.seed).subarray(0, 32), H(t.seed).subarray(32)).dk;   // 2.ª implementación
      if (t.result === 'valid' && !R.decaps(set, dk, H(t.c)).equals(H(t.K))) fails.push(`${t.tcId} oráculo K`);
      note(set + ' test', t.result);
    }
    assert.deepEqual(fails, []);
  });
  test(`Wycheproof ${set} keygen_seed: ek/dk exactas (Node y oráculo)`, () => {
    const fails = [];
    for (const t of tests(`mlkem_${n}_keygen_seed_test.json`)) {
      const seed = H(t.seed), ref = R.keyGenInternal(set, seed.subarray(0, 32), seed.subarray(32));
      if (!createPublicKey(fromSeed(set, seed)).export({ format: 'raw-public' }).equals(H(t.ek))) fails.push(`${t.tcId} Node ek`);
      if (!ref.ek.equals(H(t.ek)) || !ref.dk.equals(H(t.dk))) fails.push(`${t.tcId} oráculo`);
      note(set + ' keygen_seed', t.result);
    }
    assert.deepEqual(fails, []);
  });
  test(`Wycheproof ${set} semi_expanded_decaps: dk/c inválidos rechazados`, () => {
    const fails = [];
    for (const t of tests(`mlkem_${n}_semi_expanded_decaps_test.json`)) {
      const sk = tryOr(() => fromDk(set, H(t.dk))), K = sk && tryOr(() => decapsulate(sk, H(t.c)));
      if (t.result === 'valid' && !(K && K.equals(H(t.K)))) fails.push(`${t.tcId} valid`);
      if (t.result === 'invalid' && K) fails.push(`${t.tcId} invalid aceptado (${t.comment})`);
      note(set + ' semi_expanded', t.result);
    }
    assert.deepEqual(fails, []);
  });
  test(`Wycheproof ${set} encaps: ek inválidas rechazadas; c/K de las válidas reproducidos con m fijo`, () => {
    const fails = [];
    for (const t of tests(`mlkem_${n}_encaps_test.json`)) {
      const ok = tryOr(() => encapsulate(pubFromEk(set, H(t.ek))));
      if (t.result === 'invalid' && ok) fails.push(`${t.tcId} ek inválida aceptada`);
      if (t.result === 'valid') {
        if (!ok) fails.push(`${t.tcId} ek válida rechazada`);
        const r = R.encapsInternal(set, H(t.ek), H(t.m));
        if (!r.c.equals(H(t.c)) || !r.K.equals(H(t.K))) fails.push(`${t.tcId} c/K`);
      }
      note(set + ' encaps', t.result);
    }
    assert.deepEqual(fails, []);
  });
}

// ---- X25519 ----
const DER_PRIV = H('302e020100300506032b656e04220420'), DER_PUB = H('302a300506032b656e032100');
const nodeX = (priv, pub) => diffieHellman({
  privateKey: createPrivateKey({ key: Buffer.concat([DER_PRIV, priv]), format: 'der', type: 'pkcs8' }),
  publicKey: createPublicKey({ key: Buffer.concat([DER_PUB, pub]), format: 'der', type: 'spki' }) });
test('Wycheproof X25519: Node y oráculo; puntos de bajo orden/twist/no canónicos', () => {
  const fails = [], zero = Buffer.alloc(32);
  for (const t of tests('x25519_test.json')) {
    const pub = H(t.public), priv = H(t.private), want = H(t.shared);
    const ref = x25519(priv, pub), node = tryOr(() => nodeX(priv, pub));
    if (!ref.equals(want)) fails.push(`${t.tcId} oráculo`);
    if (t.result === 'valid' && !(node && node.equals(want))) fails.push(`${t.tcId} Node valid`);
    if (t.result === 'acceptable') {
      if (node && !node.equals(want)) fails.push(`${t.tcId} Node acepta pero difiere`);
      if (node && node.equals(zero)) fails.push(`${t.tcId} Node devuelve secreto todo ceros`);
      note('x25519', node ? 'acceptable(aceptado)' : (want.equals(zero) ? 'acceptable(rechazado, secreto=0)' : 'acceptable(rechazado, no cero)'));
    } else note('x25519', t.result);
  }
  assert.deepEqual(fails, []);
});
