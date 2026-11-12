// Análisis de tiempos estilo dudect (Welch t-test, recorte por percentiles). Informativo: NO prueba ausencia de fugas.
import { randomBytes, createPrivateKey, createPublicKey, encapsulate, decapsulate, diffieHellman, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import { encrypt, decrypt } from '../src/aead.mjs';
import * as R from '../test/support/mlkem-ref.mjs';
import { x25519 } from '../test/support/x25519-ref.mjs';
const SCALE = Number(process.env.SCALE ?? 1), THRESH = 4.5, STRONG = 10;

function welch(a, b) { const m = (x) => x.reduce((s, v) => s + v, 0) / x.length, va = (x, mu) => x.reduce((s, v) => s + (v - mu) ** 2, 0) / (x.length - 1);
  const ma = m(a), mb = m(b); return (ma - mb) / Math.sqrt(va(a, ma) / a.length + va(b, mb) / b.length); }
function measure(name, mkA, mkB, fn, N, { control = false } = {}) {
  N = Math.round(N * SCALE); const POOL = 512, A = Array.from({ length: POOL }, mkA), B = Array.from({ length: POOL }, mkB);
  for (let i = 0; i < Math.min(N, 5000); i++) { try { fn(A[i % POOL]); fn(B[i % POOL]); } catch { /* calentamiento */ } }
  const ta = [], tb = [], order = randomBytes(N);
  for (let i = 0; i < N; i++) {
    const cls = order[i] & 1, inp = (cls ? B : A)[i % POOL]; const t0 = process.hrtime.bigint();
    try { fn(inp); } catch { /* rechazo esperado */ }
    const dt = Number(process.hrtime.bigint() - t0); (cls ? tb : ta).push(dt);
  }
  const all = [...ta, ...tb].sort((x, y) => x - y); let worst = 0;
  for (const p of [1, 0.99, 0.95, 0.9]) { const cut = all[Math.floor(all.length * p) - 1]; worst = Math.max(worst, Math.abs(welch(ta.filter((v) => v <= cut), tb.filter((v) => v <= cut)))); }
  const verdict = worst > STRONG ? 'FUGA FUERTE' : worst > THRESH ? 'posible fuga' : 'sin evidencia de fuga';
  console.log(`${control ? '[control+] ' : ''}${name.padEnd(58)} |t|=${worst.toFixed(1).padStart(6)}  ${verdict}  (N=${N})`);
  return { name, worst, control };
}

const res = [];
// --- control positivo: comparación con salida temprana ---
const leakyEq = (a, b) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; };
const ref = randomBytes(2048);
res.push(measure('control: memcmp temprano (difiere byte 0 vs byte final)', () => { const x = Buffer.from(ref); x[0] ^= 1; return x; }, () => { const x = Buffer.from(ref); x[2047] ^= 1; return x; }, (x) => leakyEq(ref, x), 100000, { control: true }));
res.push(measure('control negativo: timingSafeEqual (mismo montaje)', () => { const x = Buffer.from(ref); x[0] ^= 1; return x; }, () => { const x = Buffer.from(ref); x[2047] ^= 1; return x; }, (x) => timingSafeEqual(ref, x), 100000, { control: true }));

// --- AEAD: rechazo por tag distinto en 1.er byte vs último ---
for (const alg of ['aes-256-gcm', 'chacha20-poly1305']) {
  const key = randomBytes(32), mk = (pos) => () => { const b = encrypt(alg, key, randomBytes(64)); b[pos < 0 ? b.length + pos : pos] ^= 0x80; return b; };
  res.push(measure(`decrypt ${alg}: tag erróneo en 1.er byte vs último`, mk(-16), mk(-1), (b) => decrypt(key, b), 150000));
}
// --- ML-KEM (Node/OpenSSL): ciphertext válido vs aleatorio ---
for (const set of ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']) {
  const { publicKey, privateKey } = generateKeyPairSync(set), len = encapsulate(publicKey).ciphertext.length;
  res.push(measure(`Node decapsulate ${set}: válido vs rechazo implícito`, () => encapsulate(publicKey).ciphertext, () => randomBytes(len), (c) => decapsulate(privateKey, c), 60000));
}
// --- X25519 (Node): escalar de peso Hamming alto vs bajo ---
{ const peer = randomBytes(32); peer[31] &= 127; const der = Buffer.from('302e020100300506032b656e04220420', 'hex'), pub = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), x25519(randomBytes(32), Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]))]), format: 'der', type: 'spki' });
  const mk = (fill) => () => { const k = Buffer.alloc(32, fill); for (let i = 0; i < 32; i++) k[i] ^= randomBytes(1)[0] & (fill ? 0x0f : 0xf0) ? 0 : 0; return createPrivateKey({ key: Buffer.concat([der, k]), format: 'der', type: 'pkcs8' }); };
  res.push(measure('Node X25519: escalar casi todo 1 vs casi todo 0', mk(0xff), mk(0x00), (sk) => diffieHellman({ privateKey: sk, publicKey: pub }), 40000)); }
// --- oráculos de prueba (no CT por diseño): informativo ---
{ const base = Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]);
  res.push(measure('oráculo X25519 (BigInt): escalar 0xff.. vs 0x00..', () => Buffer.alloc(32, 0xff), () => Buffer.alloc(32, 0x00), (k) => x25519(k, base), 1500)); }
{ const seed = randomBytes(64), { ek, dk } = R.keyGenInternal('ml-kem-768', seed.subarray(0, 32), seed.subarray(32));
  res.push(measure('oráculo ML-KEM-768 decaps: válido vs aleatorio', () => R.encapsInternal('ml-kem-768', ek, randomBytes(32)).c, () => randomBytes(1088), (c) => R.decaps('ml-kem-768', dk, c), 3000)); }

const ctl = res.find((r) => r.name.startsWith('control: memcmp')), neg = res.find((r) => r.name.startsWith('control negativo'));
const ok = ctl.worst > STRONG;
console.log(`\nInstrumento: control positivo ${ok ? 'DETECTADO (válido)' : 'NO detectado → resultados no concluyentes'}; control negativo |t|=${neg.worst.toFixed(1)}`);
process.exit(ok ? 0 : 2);
