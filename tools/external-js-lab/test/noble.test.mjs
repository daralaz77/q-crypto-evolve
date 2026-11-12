// 3.ª implementación independiente: @noble/post-quantum (instalada aislada en tools/js). Se omite si no está instalada.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, encapsulate, decapsulate, randomBytes } from 'node:crypto';
import * as R from './support/mlkem-ref.mjs';

const NOBLE = new URL('../tools/js/node_modules/@noble/post-quantum/ml-kem.js', import.meta.url);
const have = existsSync(NOBLE);
const noble = have ? await import(NOBLE.href) : null;
const H = (x) => Buffer.from(x, 'hex'), B = (u) => Buffer.from(u);
const NIST = (f) => JSON.parse(readFileSync(new URL(`../vectors/nist/${f}`, import.meta.url)));
const KEM = { 'ml-kem-512': 'ml_kem512', 'ml-kem-768': 'ml_kem768', 'ml-kem-1024': 'ml_kem1024' };
const grp = (d, set, fn) => d.testGroups.find((g) => g.parameterSet === set.toUpperCase() && (!fn || g.function === fn));
const exp = (d, g) => new Map(d.testGroups.find((x) => x.tgId === g.tgId).tests.map((t) => [t.tcId, t]));
const stats = {}; test.after(() => console.log('# RESUMEN NOBLE', JSON.stringify(stats)));
const note = (k) => { stats[k] = (stats[k] ?? 0) + 1; };

for (const set of Object.keys(KEM)) {
  const o = () => noble[KEM[set]];
  test(`@noble ${set}: NIST keyGen + encapsulación AFT (m fijo) + decapsulación`, { skip: !have && '@noble no instalado' }, () => {
    const KG = NIST('ML-KEM-keyGen-FIPS203-prompt.json'), KGE = NIST('ML-KEM-keyGen-FIPS203-expectedResults.json');
    const g = grp(KG, set), e = exp(KGE, g);
    for (const t of g.tests) { const k = o().keygen(Buffer.concat([H(t.d), H(t.z)])), x = e.get(t.tcId);
      assert.ok(B(k.publicKey).equals(H(x.ek)) && B(k.secretKey).equals(H(x.dk)), `keygen ${t.tcId}`); note(`${set} keyGen`); }
    const ED = NIST('ML-KEM-encapDecap-FIPS203-prompt.json'), EDE = NIST('ML-KEM-encapDecap-FIPS203-expectedResults.json');
    const ge = grp(ED, set, 'encapsulation'), ee = exp(EDE, ge);
    for (const t of ge.tests) { const r = o().encapsulate(H(t.ek), H(t.m)), x = ee.get(t.tcId);
      assert.ok(B(r.cipherText).equals(H(x.c)) && B(r.sharedSecret).equals(H(x.k)), `encaps ${t.tcId}`); note(`${set} encapsulation`); }
    const gd = grp(ED, set, 'decapsulation'), ed = exp(EDE, gd);
    for (const t of gd.tests) { assert.ok(B(o().decapsulate(H(t.c), H(t.dk))).equals(H(ed.get(t.tcId).k)), `decaps ${t.tcId}`); note(`${set} decapsulation`); }
  });
  test(`@noble ${set}: diferencial a 3 bandas (Node, oráculo, noble), 40 claves, incl. rechazo implícito`, { skip: !have && '@noble no instalado' }, () => {
    for (let i = 0; i < 40; i++) {
      const seed = randomBytes(64), nk = o().keygen(seed);
      const sk = createPrivateKey({ key: seed, format: 'raw-seed', asymmetricKeyType: set });
      assert.ok(createPublicKey(sk).export({ format: 'raw-public' }).equals(B(nk.publicKey)), 'ek Node↔noble');
      assert.ok(R.keyGenInternal(set, seed.subarray(0, 32), seed.subarray(32)).dk.equals(B(nk.secretKey)), 'dk oráculo↔noble');
      const a = o().encapsulate(nk.publicKey);                                   // noble encapsula
      assert.ok(decapsulate(sk, B(a.cipherText)).equals(B(a.sharedSecret)), 'noble→Node');
      assert.ok(R.decaps(set, B(nk.secretKey), B(a.cipherText)).equals(B(a.sharedSecret)), 'noble→oráculo');
      const b = encapsulate(createPublicKey(sk));                                // Node encapsula
      assert.ok(B(o().decapsulate(b.ciphertext, nk.secretKey)).equals(b.sharedKey), 'Node→noble');
      const bad = Buffer.from(b.ciphertext); bad[i] ^= 1;                        // rechazo implícito igual en los 3
      const n1 = B(o().decapsulate(bad, nk.secretKey));
      assert.ok(n1.equals(decapsulate(sk, bad)) && n1.equals(R.decaps(set, B(nk.secretKey), bad)), 'rechazo implícito');
      note(`${set} diferencial 3 bandas`);
    }
  });
}
