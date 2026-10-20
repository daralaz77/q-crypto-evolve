# Fuzzing, carga y fugas de los puentes `ctypes` (resultados medidos)

**Código probado:** `qce/transport/tls13_psk.py` y `qce/pqc/slhdsa.py` · **Pruebas:** `tests/test_fuzz_bridges.py`, `tests/test_load_leaks.py`, y los contadores de `tests/test_tls13_psk.py` y `tests/test_slhdsa.py`.
Medido en macOS (Apple Silicon), Python 3.14.7, OpenSSL 3.6.4. **Esto reduce el riesgo de los puentes; no sustituye la revisión humana ni demuestra seguridad de memoria.**

## 1. Fuzzing (19 pruebas, ≈ 18 s, estable en 3 ejecuciones)
- Una ClientHello **válida** capturada de un cliente real, con **un bit cambiado** en ~39 posiciones (incluido el binder y el final): ninguna completa el apretón, ninguna gasta la clave. La reproducción sin cambios tampoco completa (falta el Finished del cliente) y la clave vuelve tras el plazo.
- 22 entradas basura/truncadas/HTTP/registros con cabecera mentirosa contra el servidor; después un cliente legítimo sigue funcionando.
- 8 comportamientos de servidor hostil contra el cliente (basura pequeña y grande, alerta, cabecera y silencio, goteo lento, HTTP, cierre inmediato, mudo): siempre error tipado y dentro del plazo.
- Marcos con longitud mentirosa (> máximo, 2³¹, 2³²−1), truncados y vacíos.
- SLH-DSA: bytes arbitrarios (solo errores tipados), entradas bien formadas aleatorias (siempre rechazadas), cualquier bit cambiado de una firma válida (120 casos, siempre rechazado), firma/verificación con mensajes y contextos arbitrarios.
**Resultado: ningún defecto encontrado por el fuzzing.** Eso no prueba su ausencia.

## 2. Carga y fugas
| Medida | Resultado |
|---|---|
| 1500 apretones correctos | 1500/1500, ≈ 600 apretones/s (cliente y servidor en el mismo proceso), memoria 28,3 → 28,6 MB, descriptores y hilos constantes |
| 1500 apretones fallidos (clave equivocada) | 0 éxitos, memoria y descriptores sin cambio |
| 16 clientes en paralelo × 60 apretones | 960/960 correctos, sin descriptores colgando |
| 5000 verificaciones SLH-DSA + 50 firmas + 50 claves desde semilla | memoria y descriptores sin cambio |
| Contadores exactos de creación/liberación (`SSL_CTX`, `SSL`, `EVP_PKEY`, `EVP_MD_CTX`, `EVP_PKEY_CTX`) | equilibrados en éxito y en **todas** las rutas de fallo probadas |

**Defecto real encontrado (INC-0023):** SLH-DSA no liberaba la clave ni el contexto de resumen cuando el contexto superaba 255 bytes (la validación ocurría tras reservar). La memoria residente no lo veía (≈ 650 B por operación, y en macOS la memoria se comprime); lo vio el contador exacto. Corregido; los cinco mutantes que quitan liberaciones se detectan.

## 3. Linux (contenedor Debian 13, OpenSSL 3.5.7, Python 3.13.5, aarch64, Docker Desktop sobre macOS)
Suite completa dentro del contenedor (imagen oficial `debian:trixie`): **463 pasan, 6 omitidas (modelo formal y empaquetado, que necesitan Tamarin y el repositorio), 0 fallan.**
La primera ejecución en Linux dio 6 fallos y destapó **tres defectos reales** que macOS ocultaba:
1. **INC-0024:** sin `TCP_NODELAY` el apretón PSK iba a 21/s en vez de ≈ 600/s (Nagle + ACK retardado, ≈ 40 ms por ida y vuelta). Corregido en los dos extremos; la suite pasó de 153 s a 77 s.
2. **INC-0025:** `parse_public` trataba una clave pública hexadecimal de 3968 caracteres como ruta de archivo y Linux lanza «File name too long»; la ceremonia de firma no funcionaba. Corregido.
3. Mi propia herramienta de medida usaba `ps`, que el contenedor mínimo no trae; ahora lee `/proc/self/statm` en Linux. Y el crecimiento de memoria con 16 hilos era arenas de `malloc` y pilas de los hilos, no una fuga: con una ronda de calentamiento y tres rondas medidas, memoria, descriptores e hilos quedan constantes.

## 4. Lo que sigue sin comprobarse
- **Windows** y **Linux x86_64**: no probados (solo aarch64 en contenedor); otras versiones de OpenSSL ≥ 3.5; redes reales con pérdida.
- Seguridad de memoria del propio OpenSSL y del puente ante entradas hostiles más allá de las probadas; canales laterales.
- Carga sostenida de horas y miles de conexiones simultáneas.
- Fuzzing guiado por cobertura (p. ej. AFL/libFuzzer sobre OpenSSL) no se hizo.
