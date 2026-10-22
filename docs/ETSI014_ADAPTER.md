# Adaptador de ETSI GS QKD 014 (KME) y emulador

**Código:** `qce/qkd/etsi014.py` (adaptador), `qce/qkd/etsi014_emulator.py` (emulador, SIMULACIÓN) · **Pruebas:** `tests/test_etsi014.py` ·
**Estado: NO PROBADO contra ningún KME real. NO REVISADO por terceros.**

## 1. Qué es
Un cliente de la interfaz REST de entrega de claves de ETSI GS QKD 014 V1.1.1 que cumple el contrato de adaptadores (`qce/qkd/contract.py`):
`GET /api/v1/keys/{SAE}/status`, `POST .../enc_keys` (SAE maestra, pide 1 clave del tamaño configurado) y `POST .../dec_keys` (SAE esclava, pide por `key_ID`).
Se usa a través del `KeyBroker` (política, reserva, consumo único, cuarentena) y su clave alimenta, por ejemplo, el transporte `tls13_psk` (ver el último test de `tests/test_etsi014.py`).

## 2. Qué NO es (y por qué importa)
- **La interfaz 014 solo entrega claves.** No hay QBER, ε, amplificación de privacidad ni testigos de Bell. El adaptador **no los inventa**: se registra con el perfil `ETSI-014-KME`
  (`qce/qkd/profiles.py`), nivel de garantía «equipos de confianza», cuyo único testigo es el tamaño de clave y que **exige la ficha aprobada por una persona** con los saltos de nodos
  de confianza. Todo lo físico es confianza en el operador del KME.
- **Identidad del KME** = certificado fijado en el alta (huella SHA-256 en `public_key` del registro), no desafío-respuesta; se comprueba en cada `authenticate_device`. Un certificado
  distinto deja el dispositivo en `UNTRUSTED` y solo se recupera con `approve` de una persona nombrada.
- **Autenticación mutua:** el `ssl.SSLContext` lo aporta quien construye el transporte. Para exigir TLS 1.3 híbrido use `qce.transport.tls13.client_context(ca, cert, key)`; el adaptador no decide la política de transporte.
- El **emulador** genera las claves con `os.urandom`, autoriza a las SAE por el CN de su certificado y entrega cada `key_ID` una sola vez. Es simulación: el adaptador declara `is_simulation=True` cuando se construye así y la política de producción lo rechaza.

## 3. Validación estricta de las respuestas
Estado con todos los campos como enteros no negativos (no booleanos); exactamente una clave; `key_ID` con formato UUID, sin repetidos y solo el pedido; contenido en base64 estricto y de exactamente el tamaño pedido;
código HTTP ≠ 200 mapeado a categoría (400 → incompatibilidad de protocolo, 401 → autenticación, 503 → agotamiento de claves, otro → desconocido) con el mensaje remoto truncado; JSON no objeto → respuesta inválida;
tope de tamaño de respuesta; plazos y fallos TLS/conexión con categoría propia. Los mensajes de error **nunca** contienen la clave.

## 4. Límites
- Sin KME real: ni dialecto, ni extensiones de fabricantes (`extension_mandatory`/`optional`, `additional_slave_SAE_IDs`) ni multi-clave; solo 1 clave por petición.
- ETSI 014 no define acuse de consumo: `report_key_consumption` es un no-op declarado.
- Una conexión nueva por petición (sin reutilización); sin reintentos.
- La clave de los extremos coincide en el emulador porque comparten almacén; en un despliegue real depende del KME y del enlace entre KMEs (fuera del alcance).

## Contraste con una herramienta independiente: `qkdsec` (2026-10-22)
Para no valorarnos solo con nuestras pruebas, el emulador se contrastó con [`qkdsec`](https://github.com/John-Jepsen/qkdsec) 0.3.0 (Apache-2.0, de otra persona), que trae un cliente ETSI GS QKD 014 y una sonda de conformidad (`qkdsec doctor`). Se instaló en un entorno aparte y desechable, verificando el SHA-256 de la rueda contra el publicado en PyPI y leyendo antes su código.

**Qué encontró (dos defectos reales nuestros, ya corregidos con prueba y mutantes):**
1. **INC-0032, PKI de laboratorio:** los certificados no llevaban *Authority/Subject Key Identifier* (RFC 5280) y los clientes TLS estrictos (`requests`, el contexto por defecto de Python ≥ 3.13) los rechazaban. Nuestras pruebas usaban contextos no estrictos y `curl` los aceptaba, por eso nadie lo había visto.
2. **INC-0033, emulador:** no implementaba las formas `GET` del estándar (§5.3/§6.2: `enc_keys?number=&size=`; §5.4/§6.4: `dec_keys?key_ID=`), usaba mensajes de error propios en vez de los del estándar (`size shall be a multiple of 8`, `one or more keys specified are not found on KME`, `not all extension_mandatory parameters are supported`) y respondía 400 donde el estándar pide 401 (la SAE que no recibió la clave no puede recogerla).

**Resultado de `qkdsec doctor`:** de 1/10 sondas correctas (la alcanzabilidad fallaba por el defecto 1) a **8/10 correctas**, 1 aviso y 1 fallo. Esos dos NO se deben al emulador:
- *Aviso `error_contract_404`:* la sonda espera un 404 para una clave desconocida, pero el estándar (V1.1.1, tablas 6 y 8) solo define **400, 401 y 503**; devolver 400 es lo conforme.
- *Fallo `dec_keys_roundtrip`:* la sonda pide y recoge con **el mismo certificado**, y el estándar solo deja recoger la clave a la SAE esclava. Con la biblioteca cliente de `qkdsec` y **dos certificados** (maestra y esclava) la ida y vuelta es correcta por GET y por POST, con varias claves, con 401 para la maestra que intenta recogerla y con 400 y el texto exacto del estándar en la segunda recogida.

**Límites:** sigue siendo un emulador (claves de `os.urandom`); esto no demuestra nada sobre un KME de fabricante, ni que el estándar se cumpla en todos sus puntos (no se probaron `additional_slave_SAE_IDs` ni `max_SAE_ID_count`). Los dos resultados de la sonda que no pasan son observaciones sobre la herramienta, que conviene comunicar a su autor.

**Cómo reproducirlo** (entorno aparte; no se instala nada en el del proyecto):
```bash
python3 -m venv /tmp/qkdsec && /tmp/qkdsec/bin/pip install "qkdsec[doctor]==0.3.0"
# 1) arrancar el emulador con TLS mutuo (ver tests/test_etsi014.py::env) y anotar su puerto y los certificados de las SAE
# 2) /tmp/qkdsec/bin/qkdsec doctor https://127.0.0.1:<puerto> --slave-sae-id sae-slave --cert <maestra.pem> --key <maestra.key> --ca-cert <ca.pem>
```

