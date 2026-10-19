# Guía para quien envía el paquete (no para la persona revisora)

Todo lo que sigue lo hace **una persona**, no un agente: elegir a quién se le pide la revisión, poner el contacto y firmar. Este proyecto no puede darse por revisado sin eso.

## 1. Antes de enviar (lista)
1. Rellenar `[CONTACTO — a completar por quien envía el paquete]` en `review/LEEME.md` §6 (un correo o canal por el que la persona pueda avisar de algo grave **antes** de publicar).
2. Reconstruir el paquete sobre el commit final: `python -m qce review-package` (imprime el SHA-256 del `.zip`).
3. Comunicar ese SHA-256 por **otro canal** distinto al del archivo (el manifiesto no está firmado).
4. Elegir el alcance que se pide (§2) y a quién (§3).

## 2. Qué pedir, según el tiempo que tenga la persona
| Tiempo | Qué mirar | Dónde |
|---|---|---|
| ~2 horas | El diseño del apretón QCE1 y sus decisiones más discutibles | `docs/QCE1_SPEC.md`, `PREGUNTAS_ABIERTAS.md` preguntas 1–4 |
| ~1 día | Lo anterior + el puente `ctypes` del transporte TLS 1.3 con PSK, que es la ruta QKD recomendada y lo más delicado de escribir | `docs/TLS13_PSK_TRANSPORT.md`, `qce/transport/tls13_psk.py`, preguntas 21–22 |
| ~1 semana | Todo lo anterior + QIL1 (spec, modelo Tamarin y conformidad) + adaptador ETSI 014 + SLH-DSA | `docs/QKD_LAYER_*.md`, `formal/qil1.spthy`, `docs/ETSI014_ADAPTER.md`, `docs/SLHDSA.md`, preguntas 5–26 |

Lo que **más valor** tiene: que alguien con formación en protocolos mire (1) si `tls-unique` es suficiente como ligadura en TLS 1.3 (pregunta 21), (2) el combinador y la firma del servidor de QCE1 (preguntas 1–4) y (3) la seguridad de memoria del puente `ctypes`.

## 3. A quién (perfiles útiles)
- Criptógrafo/a de protocolos o de verificación formal (Tamarin/ProVerif) para QCE1 y QIL1.
- Ingeniero/a de seguridad con experiencia en OpenSSL y FFI para el puente `ctypes` (callbacks, `SSL_SESSION`, errores por hilo).
- Quien opere QKD real, para el perfil `ETSI-014-KME` y qué ofrece un KME de verdad.

## 4. Mensaje para la persona revisora (plantilla; editar entre corchetes)
> Hola [nombre]:
>
> Te escribo para pedirte una revisión crítica, de [2 horas / un día / una semana], de un laboratorio de criptografía poscuántica y QKD que he construido con ayuda de IA (Claude). Lo que más me ayudaría es que **encuentres lo que está mal**.
>
> Conviene que sepas, antes de empezar: **todo el código, las especificaciones, los modelos formales y las pruebas los ha escrito una IA**; hubo dos auditorías internas, también hechas por IA. **Ninguna persona lo ha revisado hasta ahora.** Contiene dos composiciones propias (el apretón QCE1 y una capa interna con clave QKD sobre TLS, QIL1) y dos puentes `ctypes` hacia OpenSSL; la clave QKD es simulada. No está pensado para producción.
>
> Te adjunto un paquete reproducible (`qce1-review-[id].zip`, SHA-256 `[hash]`, que te confirmo por [otro canal]). Empieza por `LEEME.md`; `REPRODUCCION.md` explica cómo ejecutar todo desde cero. Si prefieres centrarte en algo concreto, las preguntas abiertas están priorizadas en `PREGUNTAS_ABIERTAS.md`.
>
> Si encuentras algo grave, avísame por [contacto] antes de publicarlo. El informe puede ser texto libre o seguir `PLANTILLA_INFORME.md`; distinguir hallazgo confirmado, sospecha y pregunta ya ayuda mucho. Si quieres, tras tu revisión puedes **firmar** una declaración (ver §5).
>
> Gracias de antemano. [firma]

## 5. Ceremonia de firma (G5 revisión independiente y G6 autorización)
Las puertas G5 y G6 solo se abren con declaraciones **firmadas por personas**, ligadas al código exacto (`release_id`). El estado pasa de REVIEW_REQUIRED a VERIFIED/RELEASE_APPROVED solo así.

1. **La persona crea su identidad** en su máquina (la clave privada queda en `~/.qce-keys/<nombre>.key`, permisos 0600, **fuera del repositorio**; nunca se le da a un agente):
   `python -m qce identity new <nombre>`
   Muestra una huella de 16 caracteres y la clave pública.
2. **Se registra la clave pública** con un rol (esto no aprueba nada): `python -m qce identity register --role reviewer --identity <nombre> --pub <hex o archivo>`
   (`approver` para G6). La huella se confirma **por otro canal** con la persona, y se hace commit de `trust/registry.json`.
   *Límite declarado:* el registro vive en el repositorio; un agente con permiso de escritura podría registrar su propia clave. Por eso la huella se confirma fuera y, en producción, el registro debe anclarse fuera (HSM, raíz offline).
3. **Se fija el código**: todo cambio posterior invalida las firmas (cambia el `release_id`). Hacer commit final y correr `python -m qce gates`.
4. **La persona firma** en una terminal interactiva (el comando se niega si no lo es):
   `python -m qce sign --role reviewer --signer <nombre> --key ~/.qce-keys/<nombre>.key --verdict accept --notes "qué revisé"`
   Pide escribir la identidad para confirmar. `--verdict reject` es un veto y bloquea.
5. Volver a correr `python -m qce gates`: G5/G6 pasan de «omitida» a evaluadas. G5 exige un revisor distinto del implementador (que, mientras todo lo escriba una IA, es siempre «la IA»).

## 6. Qué NO debe hacer un agente
Crear la identidad o la clave de una persona, firmar por ella, rellenar `[CONTACTO]` con un dato inventado, o registrar una clave sin que la persona confirme la huella.
