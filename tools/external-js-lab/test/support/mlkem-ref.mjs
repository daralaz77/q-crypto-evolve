// ORÁCULO DE PRUEBAS (NO usar en producción): ML-KEM de FIPS 203 en JS puro y no constante en tiempo.
// Sirve para fijar el aleatorio `m` (Node no lo permite) y como 2.ª implementación independiente.
import { createHash } from 'node:crypto';

const Q = 3329, N = 256;
export const PARAMS = {
  'ml-kem-512': { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
  'ml-kem-768': { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
  'ml-kem-1024': { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
};
const sha3 = (alg, ...p) => createHash(alg).update(Buffer.concat(p)).digest();
const shake = (alg, len, ...p) => createHash(alg, { outputLength: len }).update(Buffer.concat(p)).digest();
const G = (...p) => sha3('sha3-512', ...p), H = (...p) => sha3('sha3-256', ...p), J = (...p) => shake('shake256', 32, ...p);
const mod = (a) => ((a % Q) + Q) % Q;
const brv7 = (i) => { let r = 0; for (let b = 0; b < 7; b++) if (i & (1 << b)) r |= 1 << (6 - b); return r; };
const pw = (b, e) => { let r = 1; for (let i = 0; i < e; i++) r = (r * b) % Q; return r; };
const ZETA = Array.from({ length: 128 }, (_, i) => pw(17, brv7(i)));
const GAMMA = Array.from({ length: 128 }, (_, i) => pw(17, 2 * brv7(i) + 1));

function ntt(f) {
  f = f.slice(); let i = 1;
  for (let len = 128; len >= 2; len >>= 1)
    for (let s = 0; s < N; s += 2 * len) { const z = ZETA[i++];
      for (let j = s; j < s + len; j++) { const t = (z * f[j + len]) % Q; f[j + len] = mod(f[j] - t); f[j] = mod(f[j] + t); } }
  return f;
}
function invNtt(f) {
  f = f.slice(); let i = 127;
  for (let len = 2; len <= 128; len <<= 1)
    for (let s = 0; s < N; s += 2 * len) { const z = ZETA[i--];
      for (let j = s; j < s + len; j++) { const t = f[j]; f[j] = mod(t + f[j + len]); f[j + len] = (z * mod(f[j + len] - t)) % Q; } }
  return f.map((x) => (x * 3303) % Q);
}
function mulNtt(f, g) {
  const h = new Array(N);
  for (let i = 0; i < 128; i++) {
    const a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
    h[2 * i] = (a0 * b0 + ((a1 * b1) % Q) * GAMMA[i]) % Q;
    h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
  }
  return h;
}
const add = (a, b) => a.map((x, i) => (x + b[i]) % Q);
const sub = (a, b) => a.map((x, i) => mod(x - b[i]));

function sampleNtt(rho, j, i) {
  for (let len = 840; ; len *= 2) {
    const B = shake('shake128', len, rho, Buffer.from([j, i])); const a = [];
    for (let p = 0; p + 2 < len && a.length < N; p += 3) {
      const d1 = B[p] + 256 * (B[p + 1] & 15), d2 = (B[p + 1] >> 4) + 16 * B[p + 2];
      if (d1 < Q) a.push(d1); if (d2 < Q && a.length < N) a.push(d2);
    }
    if (a.length === N) return a;
  }
}
function cbd(B, eta) {
  const bit = (n) => (B[n >> 3] >> (n & 7)) & 1; const f = new Array(N);
  for (let i = 0; i < N; i++) { let x = 0, y = 0;
    for (let j = 0; j < eta; j++) { x += bit(2 * i * eta + j); y += bit(2 * i * eta + eta + j); }
    f[i] = mod(x - y); }
  return f;
}
const prf = (eta, s, b) => shake('shake256', 64 * eta, s, Buffer.from([b]));
function byteEncode(f, d) {
  const out = Buffer.alloc(32 * d); let bitPos = 0;
  for (const c of f) for (let b = 0; b < d; b++, bitPos++) if ((c >> b) & 1) out[bitPos >> 3] |= 1 << (bitPos & 7);
  return out;
}
function byteDecode(B, d) {
  const f = new Array(N); let bitPos = 0;
  for (let i = 0; i < N; i++) { let v = 0; for (let b = 0; b < d; b++, bitPos++) v |= ((B[bitPos >> 3] >> (bitPos & 7)) & 1) << b; f[i] = d === 12 ? v % Q : v; }
  return f;
}
const compress = (f, d) => f.map((x) => Math.floor(((x << d) + 1664) / Q) & ((1 << d) - 1));
const decompress = (f, d) => f.map((y) => Math.floor((y * Q + (1 << (d - 1))) / (1 << d)));

const matrix = (rho, k) => Array.from({ length: k }, (_, i) => Array.from({ length: k }, (_, j) => sampleNtt(rho, j, i)));

export function keyGenInternal(set, d, z) {
  const { k, eta1 } = PARAMS[set];
  const g = G(d, Buffer.from([k])), rho = g.subarray(0, 32), sigma = g.subarray(32); let n = 0;
  const A = matrix(rho, k);
  const s = Array.from({ length: k }, () => ntt(cbd(prf(eta1, sigma, n++), eta1)));
  const e = Array.from({ length: k }, () => ntt(cbd(prf(eta1, sigma, n++), eta1)));
  const t = A.map((row, i) => row.reduce((acc, a, j) => add(acc, mulNtt(a, s[j])), e[i]));
  const ek = Buffer.concat([...t.map((x) => byteEncode(x, 12)), rho]);
  const dkPke = Buffer.concat(s.map((x) => byteEncode(x, 12)));
  return { ek, dk: Buffer.concat([dkPke, ek, H(ek), z]) };
}
function pkeEncrypt(set, ek, m, r) {
  const { k, eta1, eta2, du, dv } = PARAMS[set]; let n = 0;
  const t = Array.from({ length: k }, (_, i) => byteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12));
  const rho = ek.subarray(384 * k), A = matrix(rho, k);
  const y = Array.from({ length: k }, () => ntt(cbd(prf(eta1, r, n++), eta1)));
  const e1 = Array.from({ length: k }, () => cbd(prf(eta2, r, n++), eta2));
  const e2 = cbd(prf(eta2, r, n), eta2);
  const u = Array.from({ length: k }, (_, i) => add(invNtt(A.reduce((acc, row, j) => add(acc, mulNtt(row[i], y[j])), new Array(N).fill(0))), e1[i]));
  const mu = decompress(byteDecode(m, 1), 1);
  const v = add(add(invNtt(t.reduce((acc, ti, j) => add(acc, mulNtt(ti, y[j])), new Array(N).fill(0))), e2), mu);
  return Buffer.concat([...u.map((x) => byteEncode(compress(x, du), du)), byteEncode(compress(v, dv), dv)]);
}
export function encapsInternal(set, ek, m) {
  const g = G(m, H(ek)); return { K: g.subarray(0, 32), c: pkeEncrypt(set, ek, m, g.subarray(32)) };
}
export function decaps(set, dk, c) {
  const { k, du, dv } = PARAMS[set];
  const dkPke = dk.subarray(0, 384 * k), ek = dk.subarray(384 * k, 768 * k + 32), h = dk.subarray(768 * k + 32, 768 * k + 64), z = dk.subarray(768 * k + 64);
  const c1 = c.subarray(0, 32 * du * k), c2 = c.subarray(32 * du * k);
  const u = Array.from({ length: k }, (_, i) => decompress(byteDecode(c1.subarray(32 * du * i, 32 * du * (i + 1)), du), du));
  const v = decompress(byteDecode(c2, dv), dv);
  const s = Array.from({ length: k }, (_, i) => byteDecode(dkPke.subarray(384 * i, 384 * (i + 1)), 12));
  const sp = s.reduce((acc, si, j) => add(acc, mulNtt(si, ntt(u[j]))), new Array(N).fill(0));
  const m = byteEncode(compress(sub(v, invNtt(sp)), 1), 1);
  const g = G(m, h);
  const c2chk = pkeEncrypt(set, ek, m, g.subarray(32));
  return c2chk.equals(c) ? g.subarray(0, 32) : J(z, c);
}
