# Estudio de familias QKD y qué aporta cada una al diseño

**Alcance honesto.** El software no puede hacer física cuántica ni comprobar que un equipo diga la verdad. Lo que sí puede
hacer es exigir los **testigos** que cada protocolo debe producir, rechazar lo imposible o ausente, aplicar umbrales
(de política o de la ficha técnica aprobada por una persona) y **no confiar más de lo que el modelo de confianza permite**.
Nada de esto sustituye la evaluación física del equipo (laboratorio, certificación del fabricante). Implementación:
`qce/qkd/profiles.py`; pruebas: `tests/test_qkd_profiles.py`.

| Familia | Idea de seguridad | Qué se tomó para el diseño (no se copia el protocolo) | Testigos exigidos | Dónde se aplica |
|---|---|---|---|---|
| **BB84** (señuelo/decoy) | Preparar-y-medir con equipos de confianza; el espionaje aumenta el QBER | Umbral de QBER; **parámetro de seguridad de clave finita ε**; **amplificación de privacidad declarada** (sin ella no hay clave utilizable) | `qber`, `epsilon`, `privacy_amplification`, `decoy_ok` | `profiles.evaluate`, `KeyBroker._check_witnesses` |
| **E91** (entrelazamiento) | Violación de Bell certifica correlaciones sin depender de la afirmación del emisor | Un **testigo independiente de lo que el equipo "dice"**: CHSH `S>2+margen`; valores **imposibles** (`S>2√2`, cota de Tsirelson) delatan equipo defectuoso o mentiroso | `chsh_s` + comunes | `test_e91_chsh_bounds` |
| **MDI-QKD** | El nodo de medida/relé no es de confianza; elimina los ataques a detectores | **Minimizar la confianza**: el relé se modela como observador hostil; debe negar *explícitamente* conocer la clave (un "no sé" no basta) | `relay_holds_key=False` | `test_mdi_*` |
| **TF-QKD** (Twin-Field) | Alcance largo sin repetidores intermedios | **Contar saltos por nodos de confianza** y limitarlos por política (cada uno ve la clave); los umbrales de error de fase **solo** vienen de la ficha del equipo | `phase_error`, `trusted_hops`; ficha `phase_error_max` | `test_trusted_hops_*`, `test_tf_*` |
| **CV-QKD** (variables continuas) | Estados coherentes y detectores de telecomunicaciones | **No inventar umbrales universales**: el ruido en exceso ξ depende del equipo → ficha aprobada; exigir **calibración del ruido de disparo** (superficie de ataque conocida) | `excess_noise`, `shot_noise_calibrated`; ficha `excess_noise_max` | `test_cv_*` |
| **DI-QKD** | Seguridad sin confiar en el hardware (Bell sin lagunas) | **Techo de la escala de garantía**; exige prueba de Bell libre de lagunas; hoy es experimental → ningún adaptador debería calificar sin evidencia extraordinaria | `loophole_free`, `chsh_s` | `test_di_*` |

Corrección de nombres: **TF-QKD** = *Twin-Field QKD* (propuesta de 2018) y **CV-QKD** = *Continuous-Variable QKD*; ninguno es
"computación cuántica". Las etiquetas del listado original eran imprecisas.

## Lecciones transversales que se incorporaron
1. **Escala de garantía por modelo de confianza**, no por "calidad": `NONE < TRUSTED_DEVICES < ENTANGLEMENT_WITNESSED < MEASUREMENT_DEVICE_INDEPENDENT < DEVICE_INDEPENDENT`. La política fija el mínimo (`Policy.min_assurance`).
2. **Perfil desconocido = sin confianza** (falla cerrado): un adaptador que no declare su protocolo es rechazado.
3. **Testigos ligados a cada clave** (`key_id`): evidencia buena de una clave no sirve para otra; el broker lo comprueba tras adquirir.
4. **Plausibilidad física** antes del umbral: valores imposibles → `INVALID_RESPONSE`; sospechosos → cuarentena persistente del enlace (no se rehabilita solo).
5. **Umbrales de equipo = dato aprobado por una persona**, nunca constantes inventadas aquí. Los de política (`max_epsilon=1e-9`, `chsh_margin=0.05`, `qber_abort=0.11`) son configurables y no son estándares.
6. **Siempre en híbrido**: la clave QKD se mezcla con el secreto poscuántico (HKDF sobre el transcript); si se rompe un supuesto (p. ej. un canal lateral del detector en BB84, o la dureza de MLWE) el otro componente sigue aportando.

## Lo que NO se hace (y por qué)
- No se implementa ningún protocolo físico ni se valida hardware: no hay equipo ni documentación de fabricante.
- No se afirma que MDI/DI "sea más seguro" en este software: solo se refleja su **modelo de confianza** para decidir qué se acepta.
- No existe un adaptador ETSI GS QKD 014 ni de fabricante (`vendor_template` pendiente de documentación real).
