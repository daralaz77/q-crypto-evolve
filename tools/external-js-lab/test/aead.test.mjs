import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
const M = await import(process.env.AEAD_MODULE ?? '../src/aead.mjs');
const key = randomBytes(32), pt = Buffer.from('mensaje sintético de prueba');

test('vector oficial AES-256-GCM (McGrew-Viega TC14)', () => {
  const c = createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
  const ct = Buffer.concat([c.update(Buffer.alloc(16)), c.final()]);
  assert.equal(ct.toString('hex'), 'cea7403d4d606b6e074ec5d3baf39d18');
  assert.equal(c.getAuthTag().toString('hex'), 'd0d1c8a799996bf0265b98b5d48ab919');
});

test('vector RFC 8439 §2.8.2 ChaCha20-Poly1305', () => {
  const k = Buffer.from([...Array(32)].map((_, i) => 0x80 + i));
  const n = Buffer.from('070000004041424344454647', 'hex');
  const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
  const p = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const c = createCipheriv('chacha20-poly1305', k, n, { authTagLength: 16 }); c.setAAD(aad);
  const ct = Buffer.concat([c.update(p), c.final()]);
  assert.equal(c.getAuthTag().toString('hex'), '1ae10b594f09e26a7e902ecbd0600691');
  assert.equal(ct.subarray(0, 8).toString('hex'), 'd31a8d34648e60db');
});

for (const alg of ['aes-256-gcm', 'chacha20-poly1305']) {
  test(`${alg}: ida y vuelta con AAD`, () => {
    const aad = Buffer.from('ctx');
    assert.deepEqual(M.decrypt(key, M.encrypt(alg, key, pt, aad), aad), pt);
  });
  test(`${alg}: manipular cualquier byte es rechazado`, () => {
    const blob = M.encrypt(alg, key, pt);
    for (let i = 2; i < blob.length; i++) {
      const t = Buffer.from(blob); t[i] ^= 1;
      assert.throws(() => M.decrypt(key, t), `byte ${i} aceptado`);
    }
  });
  test(`${alg}: AAD o clave incorrectas son rechazadas`, () => {
    const blob = M.encrypt(alg, key, pt, Buffer.from('a'));
    assert.throws(() => M.decrypt(key, blob, Buffer.from('b')));
    assert.throws(() => M.decrypt(randomBytes(32), blob, Buffer.from('a')));
  });
  test(`${alg}: nonce único en 5000 cifrados`, () => {
    const s = new Set();
    for (let i = 0; i < 5000; i++) s.add(M.encrypt(alg, key, pt).subarray(2, 14).toString('hex'));
    assert.equal(s.size, 5000);
  });
}
test('rechaza algoritmo no permitido y clave corta', () => {
  assert.throws(() => M.encrypt('aes-128-ecb', key, pt));
  assert.throws(() => M.encrypt('aes-256-gcm', randomBytes(16), pt));
});

// Regresión INC-0002 (hallazgo ESLint detect-object-injection): la lista de algoritmos permitidos debe ser cerrada.
test('lista de algoritmos cerrada: claves de prototipo se rechazan con el error de política', () => {
  for (const a of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'])
    assert.throws(() => M.encrypt(a, key, pt), /no permitido/, `alg ${a}`);
});
