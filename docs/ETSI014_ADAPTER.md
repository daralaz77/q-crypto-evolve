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
