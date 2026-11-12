import { randomBytes } from 'node:crypto';
import { encrypt, decrypt } from '../src/aead.mjs';
const welch = (a, b) => { const m = (x) => x.reduce((s, v) => s + v, 0) / x.length, v = (x, mu) => x.reduce((s, y) => s + (y - mu) ** 2, 0) / (x.length - 1); const ma = m(a), mb = m(b); return (ma - mb) / Math.sqrt(v(a, ma) / a.length + v(b, mb) / b.length); };
function run(alg, posA, posB, N) {
  const key = randomBytes(32), mk = (p) => () => { const b = encrypt(alg, key, randomBytes(64)); b[b.length + p] ^= 0x80; return b; };
  const A = Array.from({ length: 512 }, mk(posA)), B = Array.from({ length: 512 }, mk(posB)); const ta = [], tb = [], o = randomBytes(N);
  for (let i = 0; i < 20000; i++) { try { decrypt(key, A[i % 512]); } catch {} try { decrypt(key, B[i % 512]); } catch {} }
  for (let i = 0; i < N; i++) { const c = o[i] & 1, x = (c ? B : A)[i % 512], t0 = process.hrtime.bigint(); try { decrypt(key, x); } catch {} (c ? tb : ta).push(Number(process.hrtime.bigint() - t0)); }
  const all = [...ta, ...tb].sort((p, q) => p - q); let w = 0;
  for (const p of [1, 0.99, 0.95, 0.9]) { const cut = all[Math.floor(all.length * p) - 1]; w = Math.max(w, Math.abs(welch(ta.filter((v) => v <= cut), tb.filter((v) => v <= cut)))); }
  return w.toFixed(1);
}
for (const alg of ['aes-256-gcm', 'chacha20-poly1305']) {
  const same = [1, 2, 3].map(() => run(alg, -16, -16, 150000)), diff = [1, 2, 3].map(() => run(alg, -16, -1, 150000));
  console.log(`${alg}: misma-vs-misma (ruido) |t| = ${same.join(', ')}   primer-vs-último byte |t| = ${diff.join(', ')}`);
}
