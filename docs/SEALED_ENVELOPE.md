# Sobre poscuántico con quórum (`qce.sealed`)

**Estado: laboratorio. Sin revisión humana externa ni prueba formal. No usar en producción.** Especificación: [`SEALED_ENVELOPE_SPEC.md`](SEALED_ENVELOPE_SPEC.md).

## Qué hace
Un archivo de larga vida (pensado contra «cosechar ahora, descifrar después») que **ninguna persona puede abrir sola**: hace falta una solicitud firmada y vigente de alguien autorizado y la participación de un quórum de custodios. Opcionalmente, además, un **candado simétrico**: aunque se rompieran X25519 y ML-KEM, sin la ficha del guardián no se lee.

| Papel | Tiene | Hace |
|---|---|---|
| Emisor | clave de firma | sella y firma |
| Solicitante | clave de firma autorizada en el archivo (y, si hay candado, un secreto de alta) | pide la apertura |
| Custodios | clave KEM + diario | entregan su participación, una vez por solicitud |
| Guardián (uno o k de n) | maestra del candado + diario | emite la ficha |
| Quien abre | clave KEM de apertura | reúne participaciones y fichas |

## Ceremonia
```bash
python -m qce.sealed keygen emisor ana
python -m qce.sealed keygen emisor gil
python -m qce.sealed keygen custodio bea
python -m qce.sealed keygen custodio carla
python -m qce.sealed keygen custodio apertura
python -m qce.sealed keygen candado plazo-2031
```
Cada clave secreta se guarda **cifrada** con una frase (mínimo 12 caracteres). Para repartir la maestra: `split-lock --lock plazo-2031.candado --k 2 --n 3 --out-prefix parte` (luego se usa `--share` en lugar de `--lock`).

```bash
python -m qce.sealed seal informe.pdf informe.qsel --sender ana.key --opener gil.pub --group direccion:2:bea.pub,carla.pub --lock plazo-2031.candado
python -m qce.sealed guardian register informe.qsel --sender-pub ana.pub --lock plazo-2031.candado --journal guardian.diario --anchor /ruta/en/otro/medio/guardian.ancla
python -m qce.sealed guardian enroll --lock plazo-2031.candado --journal guardian.diario --anchor /ruta/en/otro/medio/guardian.ancla --requester gil.pub --out gil.secreto
python -m qce.sealed stub informe.qsel --sender-pub ana.pub --out informe.resguardo
```
El resguardo (decenas de KB) basta a custodios y guardián. Para abrir:
```bash
python -m qce.sealed request informe.resguardo --sender-pub ana.pub --key gil.key --to apertura.pub --reason "auditoria 2031" --out solicitud.req
python -m qce.sealed contribute informe.resguardo --sender-pub ana.pub --key bea.key --request solicitud.req --out bea.part
python -m qce.sealed prove informe.resguardo --sender-pub ana.pub --request solicitud.req --secret gil.secreto --out solicitud.prueba
python -m qce.sealed guardian release informe.resguardo --sender-pub ana.pub --lock plazo-2031.candado --journal guardian.diario --anchor /ruta/en/otro/medio/guardian.ancla --request solicitud.req --proof solicitud.prueba --out informe.ficha
python -m qce.sealed open informe.qsel informe-abierto.pdf --sender-pub ana.pub --key apertura.key bea.part carla.part --token informe.ficha
```
La ficha y el secreto del solicitante se entregan por canales que **no dependan de clave pública**.

## Límites declarados
- Quien **abre** reconstruye la clave y ve el texto claro: es un punto único de confianza en ese momento.
- No hay revocación de custodios (hay que volver a sellar; las copias antiguas siguen valiendo) ni secreto hacia adelante. Retirar un archivo o destruir una maestra solo impide **fichas nuevas**; la destrucción no se puede demostrar sin hardware especial.
- La cabecera revela huellas, nombres de grupo, umbrales, solicitantes e identificadores de candado.
- Diario: sin ancla en otro medio, cortar el final no se detecta; quien restaure a la vez diario y ancla antiguos lo consigue. Un reloj retrasado hasta justo después del último apunte revive solicitudes.
- El emisor ve el texto claro y define la política. Quien robe el secreto de alta **y** rompa la firma del solicitante, o logre que el guardián registre un archivo falso, obtiene fichas.
- Frases débiles se pueden probar sin conexión; Python no es de tiempo constante ni borra secretos.
- X-Wing es un **borrador** de la IETF; el nivel «high» usa el combinador propio de QCE. No es interoperable con age, HPKE ni otras herramientas.
- El segundo lector (`tests/sealed_reader.py`) lo escribió el mismo autor: detecta divergencias entre código y especificación, no errores de concepto compartidos.

## Antecedentes (no se afirma novedad)
El quórum sobre sobres cifrados ya existe (p. ej. el complemento `age-plugin-sss` para `age`, que además tiene un destinatario híbrido poscuántico); también existen las claves precompartidas contra ordenadores cuánticos (RFC 8784), el borrado de claves para hacer datos irrecuperables (Perlman, *The Ephemerizer*) y los diarios de transparencia para descifrados. No se hizo búsqueda de patentes.
