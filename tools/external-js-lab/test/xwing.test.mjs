// X-Wing: vectores oficiales de la especificación + propiedades. Encaps determinista vía oráculo ML-KEM (Node no fija m).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
const X = await import(process.env.XWING_MODULE ?? '../src/xwing.mjs');
import * as R from './support/mlkem-ref.mjs';
import { x25519 } from './support/x25519-ref.mjs';
const H = (x) => Buffer.from(x, 'hex'), BASE = Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]);
const VEC = JSON.parse(readFileSync(new URL('../vectors/xwing_test-vectors.json', import.meta.url)));

test(`X-Wing: ${VEC.length} vectores oficiales — keygen, decapsulación (ruta de producción) y encapsulación determinista`, () => {
  VEC.forEach((v, i) => {
    assert.deepEqual(X.publicKey(H(v.sk)), H(v.pk), `pk #${i}`);
    assert.deepEqual(X.decaps(H(v.sk), H(v.ct)), H(v.ss), `decaps #${i}`);
    const eseed = H(v.eseed), pk = H(v.pk), pkM = pk.subarray(0, 1184), pkX = pk.subarray(1184);
    const m = R.encapsInternal('ml-kem-768', pkM, eseed.subarray(0, 32)), ekX = eseed.subarray(32);
    const ctX = x25519(ekX, BASE), ssX = x25519(ekX, pkX);
    assert.deepEqual(Buffer.concat([m.c, ctX]), H(v.ct), `ct #${i}`);
    assert.deepEqual(X.combine(m.K, ssX, ctX, pkX), H(v.ss), `ss #${i}`);
  });
});
test('X-Wing: ida y vuelta, tamaños y rechazo implícito', () => {
  const { sk, pk } = X.generateKey(); assert.equal(pk.length, 1216);
  const { ss, ct } = X.encaps(pk); assert.equal(ct.length, 1120);
  assert.deepEqual(X.decaps(sk, ct), ss);
  const bad = Buffer.from(ct); bad[10] ^= 1; assert.notDeepEqual(X.decaps(sk, bad), ss);
  const badX = Buffer.from(ct); badX[1100] ^= 1; assert.notDeepEqual(X.decaps(sk, badX), ss);
  assert.throws(() => X.decaps(sk, ct.subarray(1)));
});
test('X-Wing: encapsulaciones distintas → secretos distintos; punto X25519 de bajo orden rechazado', () => {
  const { sk, pk } = X.generateKey(); assert.notDeepEqual(X.encaps(pk).ss, X.encaps(pk).ss);
  const { ct } = X.encaps(pk), low = Buffer.from(ct); low.fill(0, 1088);
  assert.throws(() => X.decaps(sk, low));
});
