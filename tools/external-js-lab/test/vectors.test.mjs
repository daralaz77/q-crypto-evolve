// Vectores oficiales: Wycheproof (C2SP, testvectors_v1) y NIST ACVP-Server (ML-KEM FIPS 203).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gcm } from './support/gcm-ref.mjs';
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, encapsulate, decapsulate } from 'node:crypto';
const { decrypt } = await import(process.env.AEAD_MODULE ?? '../src/aead.mjs');

const load = (f) => JSON.parse(readFileSync(new URL(`../vectors/${f}`, import.meta.url)));
const H = (x) => Buffer.from(x, 'hex');
const stats = {};
const note = (k, r) => { (stats[k] ??= {})[r] = (stats[k][r] ?? 0) + 1; };
test.after(() => console.log('# RESUMEN VECTORES', JSON.stringify(stats)));

// ---------- AEAD (Wycheproof) ----------
function aeadSuite(file, algFor, wrapperId) {
  test(`Wycheproof ${file}`, () => {
    const fails = [];
    for (const g of load(file).testGroups) {
      const alg = algFor(g);
      if (!alg) { note(file, 'omitidos(tamaño no soportado por node)'); continue; }
      let nodeOK = true;
      try { createCipheriv(alg, Buffer.alloc(g.keySize / 8), Buffer.alloc(g.ivSize / 8), { authTagLength: g.tagSize / 8 }); } catch { nodeOK = false; }
      if (!nodeOK) {
        for (const t of g.tests) {
          if (alg.endsWith('-gcm') && g.ivSize > 0) { // oráculo independiente para IV que Node no admite
            const got = gcm(H(t.key), H(t.iv), H(t.aad), H(t.ct), 'dec', g.tagSize / 8, H(t.tag));
            if (t.result === 'valid') { if (!got || !got.equals(H(t.msg))) fails.push(`${t.tcId} oráculo rechaza valid`); }
            else if (t.result === 'invalid' && got) fails.push(`${t.tcId} oráculo ACEPTA invalid`);
            note(file, `iv=${g.ivSize}b vía oráculo/${t.result}`);
          } else {
            if (t.result !== 'invalid') fails.push(`${t.tcId} omitido pero es ${t.result}`);
            note(file, `iv=${g.ivSize}b rechazado por node (invalid esperado)`);
          }
        }
        continue;
      }
      for (const t of g.tests) {
        const key = H(t.key), iv = H(t.iv), aad = H(t.aad), msg = H(t.msg), ct = H(t.ct), tag = H(t.tag);
        const decOK = () => {
          const d = createDecipheriv(alg, key, iv, { authTagLength: g.tagSize / 8 });
          d.setAAD(aad); d.setAuthTag(tag);
          return Buffer.concat([d.update(ct), d.final()]);
        };
        let got = null; try { got = decOK(); } catch { /* rechazo */ }
        if (t.result === 'valid') {
          if (!got || !got.equals(msg)) fails.push(`${t.tcId} valid rechazado`);
          const c = createCipheriv(alg, key, iv, { authTagLength: g.tagSize / 8 }); c.setAAD(aad);
          const enc = Buffer.concat([c.update(msg), c.final()]);
          if (!enc.equals(ct) || !c.getAuthTag().equals(tag)) fails.push(`${t.tcId} cifrado no coincide`);
        } else if (t.result === 'invalid') {
          if (got) fails.push(`${t.tcId} invalid ACEPTADO (${t.comment})`);
        } // acceptable: sin aserción, solo se cuenta
        note(file, t.result);
        // wrapper propio (solo clave 256, iv 96, tag 128)
        if (g.keySize === 256 && g.ivSize === 96 && g.tagSize === 128) {
          const blob = Buffer.concat([Buffer.from([1, wrapperId]), iv, ct, tag]);
          let w = null; try { w = decrypt(key, blob, aad); } catch { /* rechazo */ }
          if (t.result === 'valid' && (!w || !w.equals(msg))) fails.push(`${t.tcId} wrapper rechaza valid`);
          if (t.result === 'invalid' && w) fails.push(`${t.tcId} wrapper ACEPTA invalid`);
          note(file + ' [wrapper]', t.result);
        }
      }
    }
    assert.deepEqual(fails, []);
  });
}
test('Wycheproof AES-GCM: oráculo independiente coincide en TODOS los vectores', () => {
  const fails = []; let n = 0;
  for (const g of load('aes_gcm_test.json').testGroups) for (const t of g.tests) {
    if (g.ivSize === 0) continue;
    const got = gcm(H(t.key), H(t.iv), H(t.aad), H(t.ct), 'dec', g.tagSize / 8, H(t.tag)); n++;
    if (t.result === 'valid' && !(got && got.equals(H(t.msg)))) fails.push(`${t.tcId} valid`);
    if (t.result === 'invalid' && got) fails.push(`${t.tcId} invalid aceptado`);
  }
  note('oráculo GCM vs vectores', n); assert.deepEqual(fails, []);
});
aeadSuite('aes_gcm_test.json', (g) => ({ 128: 'aes-128-gcm', 192: 'aes-192-gcm', 256: 'aes-256-gcm' })[g.keySize], 1);
aeadSuite('chacha20_poly1305_test.json', () => 'chacha20-poly1305', 2);

// ---------- ML-KEM-768 ----------
const OID768 = H('0609608648016503040402');
const lenEnc = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (t, b) => Buffer.concat([Buffer.from([t]), lenEnc(b.length), b]);
// PKCS#8 con clave expandida (CHOICE expandedKey = OCTET STRING), para importar dk "semi-expandida".
const pkcs8Expanded = (dk) => tlv(0x30, Buffer.concat([H('020100'), tlv(0x30, OID768), tlv(4, tlv(4, dk))]));
const fromSeed = (seed) => createPrivateKey({ key: seed, format: 'raw-seed', asymmetricKeyType: 'ml-kem-768' });
const fromDk = (dk) => createPrivateKey({ key: pkcs8Expanded(dk), format: 'der', type: 'pkcs8' });
const pubFromEk = (ek) => createPublicKey({ key: ek, format: 'raw-public', asymmetricKeyType: 'ml-kem-768' });
const tryOr = (f, d = null) => { try { return f(); } catch { return d; } };

test('Wycheproof mlkem_768_test: semilla→ek, decapsulación y rechazo implícito', () => {
  const fails = [];
  for (const g of load('mlkem_768_test.json').testGroups) for (const t of g.tests) {
    const sk = tryOr(() => fromSeed(H(t.seed)));
    if (!sk) { if (t.result !== 'invalid') fails.push(`${t.tcId} semilla válida rechazada`); note('mlkem_768_test', 'invalid(semilla rechazada)'); continue; }
    if (!createPublicKey(sk).export({ format: 'raw-public' }).equals(H(t.ek))) fails.push(`${t.tcId} ek`);
    const K = tryOr(() => decapsulate(sk, H(t.c)));
    if (t.result === 'valid' && !(K && K.equals(H(t.K)))) fails.push(`${t.tcId} K distinta`);
    if (t.result === 'invalid' && K && K.equals(H(t.K))) fails.push(`${t.tcId} invalid acepta K`);
    note('mlkem_768_test', t.result);
  }
  assert.deepEqual(fails, []);
});

test('Wycheproof mlkem_768_keygen_seed: ek exacta y dk coherente (cruce encaps/decaps)', () => {
  const fails = [];
  for (const g of load('mlkem_768_keygen_seed_test.json').testGroups) for (const t of g.tests) {
    const sk = fromSeed(H(t.seed));
    if (!createPublicKey(sk).export({ format: 'raw-public' }).equals(H(t.ek))) fails.push(`${t.tcId} ek`);
    const { sharedKey, ciphertext } = encapsulate(pubFromEk(H(t.ek)));
    if (!decapsulate(sk, ciphertext).equals(sharedKey)) fails.push(`${t.tcId} cruce`);
    const sk2 = tryOr(() => fromDk(H(t.dk)));           // dk expandida del vector
    if (!sk2 || !decapsulate(sk2, ciphertext).equals(sharedKey)) fails.push(`${t.tcId} dk vector`);
    note('mlkem_768_keygen_seed', t.result);
  }
  assert.deepEqual(fails, []);
});

test('Wycheproof mlkem_768_semi_expanded_decaps: dk/c inválidos rechazados', () => {
  const fails = [];
  for (const g of load('mlkem_768_semi_expanded_decaps_test.json').testGroups) for (const t of g.tests) {
    const sk = tryOr(() => fromDk(H(t.dk)));
    const K = sk && tryOr(() => decapsulate(sk, H(t.c)));
    if (t.result === 'valid' && !(K && K.equals(H(t.K)))) fails.push(`${t.tcId} valid falla`);
    if (t.result === 'invalid' && K) fails.push(`${t.tcId} invalid ACEPTADO (${t.comment})`);
    note('mlkem_768_semi_expanded_decaps', t.result);
  }
  assert.deepEqual(fails, []);
});

test('Wycheproof mlkem_768_encaps: ek inválidas (ModulusOverflow) rechazadas', () => {
  const fails = [];
  for (const g of load('mlkem_768_encaps_test.json').testGroups) for (const t of g.tests) {
    const ok = tryOr(() => encapsulate(pubFromEk(H(t.ek))));
    if (t.result === 'invalid' && ok) fails.push(`${t.tcId} ek inválida aceptada`);
    if (t.result === 'valid' && !ok) fails.push(`${t.tcId} ek válida rechazada`);
    note('mlkem_768_encaps', t.result);
  }
  assert.deepEqual(fails, []);
});

// ---------- NIST ACVP (FIPS 203) ----------
const group = (doc, fn) => doc.testGroups.find((g) => g.parameterSet === 'ML-KEM-768' && (!fn || g.function === fn));
const byId = (arr) => new Map(arr.map((t) => [t.tcId, t]));

test('NIST ACVP ML-KEM-keyGen-FIPS203 (768): d||z → ek, dk', () => {
  const p = group(load('nist/ML-KEM-keyGen-FIPS203-prompt.json'));
  const e = byId(load('nist/ML-KEM-keyGen-FIPS203-expectedResults.json').testGroups[p.tgId - 1].tests);
  const fails = [];
  for (const t of p.tests) {
    const exp = e.get(t.tcId);
    const sk = fromSeed(Buffer.concat([H(t.d), H(t.z)]));
    if (!createPublicKey(sk).export({ format: 'raw-public' }).equals(H(exp.ek))) fails.push(`${t.tcId} ek`);
    const { sharedKey, ciphertext } = encapsulate(pubFromEk(H(exp.ek)));
    const skDk = fromDk(H(exp.dk));
    if (!decapsulate(sk, ciphertext).equals(sharedKey) || !decapsulate(skDk, ciphertext).equals(sharedKey)) fails.push(`${t.tcId} dk`);
    note('NIST keyGen 768', 'ok');
  }
  assert.deepEqual(fails, []);
});

test('NIST ACVP ML-KEM-encapDecap (768): decapsulación y comprobaciones de clave', () => {
  const P = load('nist/ML-KEM-encapDecap-FIPS203-prompt.json'), E = load('nist/ML-KEM-encapDecap-FIPS203-expectedResults.json');
  const exp = (g) => byId(E.testGroups.find((x) => x.tgId === g.tgId).tests);
  const fails = [];
  const gd = group(P, 'decapsulation'), ed = exp(gd);
  for (const t of gd.tests) {
    const K = tryOr(() => decapsulate(fromDk(H(t.dk)), H(t.c)));
    if (!K || !K.equals(H(ed.get(t.tcId).k))) fails.push(`decaps ${t.tcId}`);
    note('NIST decapsulation 768', 'ok');
  }
  const ge = group(P, 'encapsulationKeyCheck'), ee = exp(ge);
  for (const t of ge.tests) {
    const accepted = !!tryOr(() => encapsulate(pubFromEk(H(t.ek))));
    if (accepted !== ee.get(t.tcId).testPassed) fails.push(`ekCheck ${t.tcId} esperado ${ee.get(t.tcId).testPassed}`);
    note('NIST encapsulationKeyCheck 768', 'ok');
  }
  const gk = group(P, 'decapsulationKeyCheck'), ek = exp(gk);
  for (const t of gk.tests) {
    const accepted = !!tryOr(() => fromDk(H(t.dk)));
    if (accepted !== ek.get(t.tcId).testPassed) fails.push(`dkCheck ${t.tcId} esperado ${ek.get(t.tcId).testPassed}`);
    note('NIST decapsulationKeyCheck 768', 'ok');
  }
  assert.deepEqual(fails, []);
});
