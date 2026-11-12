// ORÁCULO DE PRUEBAS: X25519 (RFC 7748 §5) con BigInt, escalera de Montgomery. No constante en tiempo.
const P = (1n << 255n) - 19n, A24 = 121665n;
const inv = (a) => { let r = 1n, b = a % P, e = P - 2n; while (e) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; };
const le = (b) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
export function x25519(k, u) {
  const kk = Buffer.from(k); kk[0] &= 248; kk[31] &= 127; kk[31] |= 64;
  const ub = Buffer.from(u); ub[31] &= 127;
  const kn = le(kk), x1 = le(ub) % P; let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, sw = 0n;
  for (let t = 254n; t >= 0n; t--) {
    const kt = (kn >> t) & 1n; sw ^= kt; if (sw) [x2, x3, z2, z3] = [x3, x2, z3, z2]; sw = kt;
    const a = (x2 + z2) % P, aa = (a * a) % P, b = (x2 - z2 + P) % P, bb = (b * b) % P, e = (aa - bb + P) % P;
    const c = (x3 + z3) % P, d = (x3 - z3 + P) % P, da = (d * a) % P, cb = (c * b) % P;
    x3 = ((da + cb) ** 2n) % P; z3 = (x1 * (((da - cb + P) % P) ** 2n)) % P; x2 = (aa * bb) % P; z2 = (e * ((aa + A24 * e) % P)) % P;
  }
  if (sw) [x2, z2] = [x3, z3];
  const out = (x2 * inv(z2)) % P; return Buffer.from(out.toString(16).padStart(64, '0'), 'hex').reverse();
}
