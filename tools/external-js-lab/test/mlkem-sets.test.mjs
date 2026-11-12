// ML-KEM-512/768/1024: vectores NIST ACVP (incluida encapsulación con m fijo vía oráculo) + diferencial Node↔oráculo.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, encapsulate, decapsulate, randomBytes } from 'node:crypto';
import * as R from './support/mlkem-ref.mjs';

const load = (f) => JSON.parse(readFileSync(new URL(`../vectors/nist/${f}`, import.meta.url)));
const H = (x) => Buffer.from(x, 'hex');
const stats = {}; test.after(() => console.log('# RESUMEN ML-KEM', JSON.stringify(stats)));
const note = (k) => { stats[k] = (stats[k] ?? 0) + 1; };
const OID = { 'ml-kem-512': '01', 'ml-kem-768': '02', 'ml-kem-1024': '03' };
const lenEnc = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (t, b) => Buffer.concat([Buffer.from([t]), lenEnc(b.length), b]);
const fromDk = (set, dk) => createPrivateKey({ key: tlv(0x30, Buffer.concat([H('020100'), tlv(0x30, H('06096086480165030404' + OID[set])), tlv(4, tlv(4, dk))])), format: 'der', type: 'pkcs8' });
const fromSeed = (set, seed) => createPrivateKey({ key: seed, format: 'raw-seed', asymmetricKeyType: set });
const pubFromEk = (set, ek) => createPublicKey({ key: ek, format: 'raw-public', asymmetricKeyType: set });
const tryOr = (f) => { try { return f(); } catch { return null; } };
const sets = Object.keys(R.PARAMS), ps = (s) => s.toUpperCase().replace('ML-KEM-', 'ML-KEM-');
const KG = load('ML-KEM-keyGen-FIPS203-prompt.json'), KGE = load('ML-KEM-keyGen-FIPS203-expectedResults.json');
const ED = load('ML-KEM-encapDecap-FIPS203-prompt.json'), EDE = load('ML-KEM-encapDecap-FIPS203-expectedResults.json');
const grp = (doc, set, fn) => doc.testGroups.find((g) => g.parameterSet === ps(set) && (!fn || g.function === fn));
const exp = (doc, g) => new Map(doc.testGroups.find((x) => x.tgId === g.tgId).tests.map((t) => [t.tcId, t]));

for (const set of sets) {
  test(`${set}: NIST keyGen — Node y oráculo coinciden con ek/dk oficiales`, () => {
    const g = grp(KG, set), e = exp(KGE, g);
    for (const t of g.tests) {
      const seed = Buffer.concat([H(t.d), H(t.z)]), x = e.get(t.tcId);
      const node = createPublicKey(fromSeed(set, seed)).export({ format: 'raw-public' });
      const ref = R.keyGenInternal(set, H(t.d), H(t.z));
      assert.ok(node.equals(H(x.ek)), `Node ek ${t.tcId}`);
      assert.ok(ref.ek.equals(H(x.ek)) && ref.dk.equals(H(x.dk)), `oráculo ${t.tcId}`);
      note(`${set} keyGen`);
    }
  });
  test(`${set}: NIST encapsulación AFT con m fijo (oráculo) y decapsulación con Node`, () => {
    const g = grp(ED, set, 'encapsulation'), e = exp(EDE, g);
    for (const t of g.tests) {
      const r = R.encapsInternal(set, H(t.ek), H(t.m)), x = e.get(t.tcId);
      assert.ok(r.c.equals(H(x.c)) && r.K.equals(H(x.k)), `encaps ${t.tcId}`);
      note(`${set} encapsulation`);
    }
    const gd = grp(ED, set, 'decapsulation'), ed = exp(EDE, gd);
    for (const t of gd.tests) {
      const want = H(ed.get(t.tcId).k);
      assert.ok(decapsulate(fromDk(set, H(t.dk)), H(t.c)).equals(want), `Node decaps ${t.tcId}`);
      assert.ok(R.decaps(set, H(t.dk), H(t.c)).equals(want), `oráculo decaps ${t.tcId}`);
      note(`${set} decapsulation`);
    }
  });
  test(`${set}: NIST comprobación de claves (ek módulo, dk hash/estructura)`, () => {
    const ge = grp(ED, set, 'encapsulationKeyCheck'), ee = exp(EDE, ge);
    for (const t of ge.tests) { assert.equal(!!tryOr(() => encapsulate(pubFromEk(set, H(t.ek)))), ee.get(t.tcId).testPassed, `ek ${t.tcId}`); note(`${set} ekCheck`); }
    const gk = grp(ED, set, 'decapsulationKeyCheck'), ek = exp(EDE, gk);
    for (const t of gk.tests) { assert.equal(!!tryOr(() => fromDk(set, H(t.dk))), ek.get(t.tcId).testPassed, `dk ${t.tcId}`); note(`${set} dkCheck`); }
  });
  test(`${set}: diferencial Node↔oráculo, 40 claves aleatorias en ambos sentidos`, () => {
    for (let i = 0; i < 40; i++) {
      const seed = randomBytes(64), sk = fromSeed(set, seed);
      const ek = createPublicKey(sk).export({ format: 'raw-public' });
      const ref = R.keyGenInternal(set, seed.subarray(0, 32), seed.subarray(32));
      assert.ok(ref.ek.equals(ek), 'ek');
      const a = encapsulate(createPublicKey(sk));                       // Node encapsula → oráculo decapsula
      assert.ok(R.decaps(set, ref.dk, a.ciphertext).equals(a.sharedKey), 'Node→oráculo');
      const b = R.encapsInternal(set, ek, randomBytes(32));             // oráculo encapsula → Node decapsula
      assert.ok(decapsulate(sk, b.c).equals(b.K), 'oráculo→Node');
      const bad = Buffer.from(b.c); bad[i] ^= 1;                        // rechazo implícito coincide
      assert.ok(decapsulate(sk, bad).equals(R.decaps(set, ref.dk, bad)), 'rechazo implícito');
      note(`${set} diferencial`);
    }
  });
}
