// X-Wing KEM (draft-connolly-cfrg-xwing-kem): X25519 + ML-KEM-768, combinador SHA3-256. Alternativa revisada al híbrido propio.
import { createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, encapsulate, decapsulate, randomBytes } from 'node:crypto';

export const LABEL = Buffer.from('5c2e2f2f5e5c', 'hex'); // "\.//^\"
export const SIZES = { sk: 32, pk: 1216, ct: 1120, ss: 32 };
const X_PRIV = Buffer.from('302e020100300506032b656e04220420', 'hex'), X_PUB = Buffer.from('302a300506032b656e032100', 'hex');
const xPriv = (k) => createPrivateKey({ key: Buffer.concat([X_PRIV, k]), format: 'der', type: 'pkcs8' });
const xPub = (k) => createPublicKey({ key: Buffer.concat([X_PUB, k]), format: 'der', type: 'spki' });
const xPubFromPriv = (k) => createPublicKey(xPriv(k)).export({ format: 'der', type: 'spki' }).subarray(-32);
const xdh = (priv, pub) => diffieHellman({ privateKey: xPriv(priv), publicKey: xPub(pub) }); // Node rechaza puntos de bajo orden (secreto 0)

export const combine = (ssM, ssX, ctX, pkX) => createHash('sha3-256').update(Buffer.concat([ssM, ssX, ctX, pkX, LABEL])).digest();

export function expand(sk) {
  if (sk.length !== 32) throw new Error('sk debe tener 32 bytes');
  const e = createHash('shake256', { outputLength: 96 }).update(sk).digest();
  const mlSeed = e.subarray(0, 64), skX = e.subarray(64, 96);
  const mlKey = createPrivateKey({ key: mlSeed, format: 'raw-seed', asymmetricKeyType: 'ml-kem-768' });
  const pkM = createPublicKey(mlKey).export({ format: 'raw-public' });
  return { mlKey, pkM, skX, pkX: xPubFromPriv(skX) };
}
export const generateKey = () => { const sk = randomBytes(32); const x = expand(sk); return { sk, pk: Buffer.concat([x.pkM, x.pkX]) }; };
export const publicKey = (sk) => { const x = expand(sk); return Buffer.concat([x.pkM, x.pkX]); };

export function encaps(pk) {
  if (pk.length !== SIZES.pk) throw new Error('pk de tamaño inválido');
  const pkM = pk.subarray(0, 1184), pkX = pk.subarray(1184);
  const ekX = randomBytes(32), ctX = xPubFromPriv(ekX), ssX = xdh(ekX, pkX);
  const { sharedKey: ssM, ciphertext: ctM } = encapsulate(createPublicKey({ key: pkM, format: 'raw-public', asymmetricKeyType: 'ml-kem-768' }));
  return { ss: combine(ssM, ssX, ctX, pkX), ct: Buffer.concat([ctM, ctX]) };
}
export function decaps(sk, ct) {
  if (ct.length !== SIZES.ct) throw new Error('ct de tamaño inválido');
  const x = expand(sk), ctM = ct.subarray(0, 1088), ctX = ct.subarray(1088);
  return combine(decapsulate(x.mlKey, ctM), xdh(x.skX, ctX), ctX, x.pkX);
}
