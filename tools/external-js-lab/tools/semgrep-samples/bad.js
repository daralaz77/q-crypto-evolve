// MUESTRA DELIBERADAMENTE INSEGURA: control positivo de las reglas de Semgrep. No se usa en el laboratorio.
const { createHash, createCipheriv, createDecipheriv } = require('node:crypto');
createHash("md5");
createCipheriv("aes-128-ecb", Buffer.alloc(16), null);
createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12));
createCipheriv("aes-256-gcm", "0123456789abcdef0123456789abcdef", iv);
const r = Math.random();
function bad(key, iv, ct) { const d = createDecipheriv("aes-256-gcm", key, iv); return Buffer.concat([d.update(ct), d.final()]); }
