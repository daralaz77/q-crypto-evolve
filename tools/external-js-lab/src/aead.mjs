// Módulo A — cifrado autenticado (AES-256-GCM / ChaCha20-Poly1305) con node:crypto.
// Formato: [ver=1][alg][nonce 12][ciphertext][tag 16]. Nonce aleatorio CSPRNG por mensaje.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGS = new Map([[1, 'aes-256-gcm'], [2, 'chacha20-poly1305']]);
const IDS = new Map([['aes-256-gcm', 1], ['chacha20-poly1305', 2]]);
const NONCE = 12, TAG = 16, KEY = 32;

export function encrypt(alg, key, plaintext, aad = Buffer.alloc(0)) {
  if (!IDS.has(alg)) throw new Error('algoritmo no permitido');
  if (key.length !== KEY) throw new Error('clave debe tener 32 bytes');
  const nonce = randomBytes(NONCE);
  const c = createCipheriv(alg, key, nonce, { authTagLength: TAG });
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([Buffer.from([1, IDS.get(alg)]), nonce, ct, c.getAuthTag()]);
}

export function decrypt(key, blob, aad = Buffer.alloc(0)) {
  if (key.length !== KEY) throw new Error('clave debe tener 32 bytes');
  if (blob.length < 2 + NONCE + TAG || blob[0] !== 1 || !ALGS.has(blob[1])) throw new Error('formato inválido');
  const nonce = blob.subarray(2, 2 + NONCE);
  const tag = blob.subarray(blob.length - TAG);
  const ct = blob.subarray(2 + NONCE, blob.length - TAG);
  const d = createDecipheriv(ALGS.get(blob[1]), key, nonce, { authTagLength: TAG });
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]); // lanza si el tag no verifica
}
