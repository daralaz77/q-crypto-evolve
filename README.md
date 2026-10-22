# Q-Crypto Evolve — laboratorio

Plataforma de ingeniería criptográfica evolutiva (skills `q-crypto-evolve` 3.0 y `q-crypto-qkd-adapters` 1.0).
**Estado: laboratorio, sin auditoría externa. Lee `LIMITATIONS.md` antes de confiar en nada.**

> **Estado / Status:** laboratorio, sin revisión humana externa. *Research lab; no external human review.* **No usar en producción / Do not use in production.**
>
> **Transparencia sobre IA / AI disclosure:** el código, las pruebas, los modelos formales y la documentación los escribió una instancia de Claude (Anthropic) bajo puertas de verificación (pruebas, mutación, incidentes, paquete de revisión reproducible). Las firmas de personas que exige el método (puertas G5 y G6) siguen **pendientes**. *The code, tests, formal models and documentation were written by an instance of Claude (Anthropic) under verification gates; the human sign-offs the method requires (gates G5/G6) are still pending.*
>
> **Licencia / License:** [Apache-2.0](LICENSE) · [NOTICE](NOTICE) · [avisos de terceros](THIRD_PARTY_NOTICES.md) · **Vulnerabilidades / Security:** [SECURITY.md](SECURITY.md)

```bash
cd ~/Claude/q-crypto-evolve
.venv/bin/python -m qce test      # batería completa (≈1 s)
.venv/bin/python -m qce scan      # malos usos, secretos, dependencias (pip-audit, con red)
.venv/bin/python -m qce mutate    # ¿las pruebas detectan controles de seguridad rotos?
.venv/bin/python -m qce gates     # G1–G6 completas → estado (REVIEW_REQUIRED/VERIFIED/…)
.venv/bin/python -m qce gates --fast   # sin mutación ni dependencias: NUNCA promocionable
.venv/bin/python -m qce demo      # fallo → incidente → reparación → regresión → bloqueo → reversión
.venv/bin/python -m qce release   # snapshot verificable (no lo marca estable)
.venv/bin/python -m qce bench     # rendimiento (no es argumento de seguridad)
```

| Carpeta | Contenido |
|---|---|
| `qce/core` | política y registro de suites, codificación estricta, cadena de hashes, errores |
| `qce/pqc` | KEM híbrido X25519+ML-KEM-768, firma híbrida Ed25519+ML-DSA-65 |
| `qce/symmetric` | AEAD con nonce por contador, ventana anti-repetición, HKDF |
| `qce/key_management` | ciclo de vida, envelope, vault cifrado con anti-restauración |
| `qce/protocols` | handshake `QCE1` (no revisado) y capa de registros |
| `qce/qkd/etsi014.py` | adaptador de ETSI GS QKD 014 (KME) + emulador (simulación): `docs/ETSI014_ADAPTER.md` |
| `qce/transport/hsm_tls.py` | servidor TLS 1.3 híbrido con la clave privada en un HSM/token PKCS#11 (probado con SoftHSM): `docs/HSM.md` |
| `qce/core/openssl_ffi.py` | carga de OpenSSL ≥ 3.5 por `ctypes` (PSK, HSM y SLH-DSA la comparten) |
| `qce/evolve/mutants/` | los 361 mutantes como datos, un módulo por familia |
| `qce/security/approvals.py` | declaraciones firmadas de implementador, revisor y aprobador (G5/G6) |
| `qce/evolve/ceremony.py` | ceremonia de firma humana G5/G6 (`python -m qce identity new|register`, `python -m qce sign`): `review/GUIA_PARA_ENVIAR.md` §5 |
| `qce/evolve/supply_chain.py` | hashes de dependencias + SBOM CycloneDX (`python -m qce supply-chain`): `docs/SUPPLY_CHAIN.md` |
| `qce/pqc/slhdsa.py` | SLH-DSA-SHA2-128s por el `libcrypto` del sistema: `docs/SLHDSA.md` |
| `qce/transport` | **transporte recomendado**: TLS 1.3 con X25519MLKEM768 obligatorio, atestación y falla cerrado (`python -m qce tls-check`); `custody.py` guarda la clave del servidor en el KeyStore; `tls13_psk.py` = **ruta QKD recomendada**: TLS 1.3 estándar con PSK externa derivada de la clave QKD y X25519MLKEM768 (`docs/TLS13_PSK_TRANSPORT.md`; puente ctypes NO REVISADO); `qkd_layer.py` = capa interna con clave QKD sobre TLS (QIL1, **NO REVISADA**, `docs/QKD_LAYER_SPEC.md`) |
| `qce/qkd` | contrato de adaptador, registro de dispositivos, simulador, broker de claves |
| `qce/security` | escáner de secretos, malos usos (AST), auditoría de dependencias |
| `qce/evolve` | mutación, puertas, máquina de estados, firmas de revisión/aprobación, demo |
| `qce/recovery` | manifiestos, snapshots, reversión que no toca claves ni evidencia |
| `learning/` | `incidents.jsonl`, `tasks.jsonl`, `version_history.jsonl` (cadenas de hashes) |
| `decisions/`, `THREAT_MODEL.md`, `LIMITATIONS.md` | decisiones, amenazas ↔ pruebas, límites |
| `benchmarks/` | resultados reproducibles (`gates_latest.json`, `demo_latest.json`, `bench_latest.json`) |
