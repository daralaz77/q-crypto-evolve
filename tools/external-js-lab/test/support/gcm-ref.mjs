// ORÁCULO DE PRUEBAS: AES-GCM (NIST SP 800-38D) con GHASH en BigInt; admite IV de cualquier longitud ≥1 y tags truncados.
import { createCipheriv } from 'node:crypto';
const R = 0xe1n << 120n, M128 = (1n << 128n) - 1n;
const toBig = (b) => BigInt('0x' + (b.length ? b.toString('hex') : '0'));
const toBuf = (n, len = 16) => Buffer.from(n.toString(16).padStart(len * 2, '0'), 'hex');
function mul(x, y) { let z = 0n, v = y; for (let i = 127; i >= 0; i--) { if ((x >> BigInt(i)) & 1n) z ^= v; v = v & 1n ? (v >> 1n) ^ R : v >> 1n; } return z; }
function ghash(h, data) { let y = 0n; for (let i = 0; i < data.length; i += 16) { const b = Buffer.alloc(16); data.copy(b, 0, i, Math.min(i + 16, data.length)); y = mul(y ^ toBig(b), h); } return y; }
const pad = (b) => Buffer.concat([b, Buffer.alloc((16 - (b.length % 16)) % 16)]);
const len64 = (bits) => toBuf(BigInt(bits), 8);
export function gcm(key, iv, aad, input, mode, tagLen = 16, tagIn) {
  const ecb = (blk) => { const c = createCipheriv(`aes-${key.length * 8}-ecb`, key, null); c.setAutoPadding(false); return Buffer.concat([c.update(blk), c.final()]); };
  const h = toBig(ecb(Buffer.alloc(16)));
  const j0 = iv.length === 12 ? Buffer.concat([iv, Buffer.from([0, 0, 0, 1])]) : toBuf(ghash(h, Buffer.concat([pad(iv), len64(0), len64(iv.length * 8)])));
  const ctr = (n) => { const b = Buffer.from(j0); b.writeUInt32BE((b.readUInt32BE(12) + n) >>> 0, 12); return b; };
  const out = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i += 16) { const ks = ecb(ctr(i / 16 + 1)); for (let j = 0; j < 16 && i + j < input.length; j++) out[i + j] = input[i + j] ^ ks[j]; }
  const ct = mode === 'enc' ? out : input;
  const s = ghash(h, Buffer.concat([pad(aad), pad(ct), len64(aad.length * 8), len64(ct.length * 8)]));
  const tag = toBuf(s ^ toBig(ecb(j0))).subarray(0, tagLen);
  if (mode === 'enc') return { ct: out, tag };
  return tag.equals(tagIn) ? out : null;
}
