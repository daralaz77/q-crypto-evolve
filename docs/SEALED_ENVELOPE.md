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
Cada clave secreta se guarda **cifrada** con una frase (mínimo 12 caracteres; con `--generate-passphrase` se genera una de 128 bits y se muestra una sola vez). Para repartir la maestra: `split-lock --lock plazo-2031.candado --k 2 --n 3 --out-prefix parte` (luego se usa `--share` en lugar de `--lock`).

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

## Rotación y revocación
Quitar a un custodio (o cambiar solicitantes, umbrales o candados) es volver a sellar **y retirar el archivo anterior**:
```bash
python -m qce.sealed reseal informe.qsel informe-2.qsel bea.part carla.part --sender-pub ana.pub --key apertura.key --token informe.ficha --new-sender ana.key --opener gil.pub --group direccion:2:bea.pub,carla.pub --lock plazo-2031.candado
python -m qce.sealed guardian register informe-2.qsel --sender-pub ana.pub --lock plazo-2031.candado --journal guardian.diario
python -m qce.sealed guardian withdraw informe.qsel --sender-pub ana.pub --lock plazo-2031.candado --journal guardian.diario
python -m qce.sealed custodian withdraw informe.qsel --sender-pub ana.pub --key bea.key
```
`reseal` no escribe el claro en disco, hereda cifrado y modo, y se niega a quitar candados sin `--drop-locks`. Si el guardián usa anclas, repite `--anchor` en sus comandos.

Qué consigue cada retirada:
- **Con candado:** el guardián no vuelve a dar fichas para el archivo viejo; un excustodio con su copia no la abre sin una ficha emitida antes.
- **Sin candado:** basta con que retiren el archivo tantos custodios honrados que los restantes no lleguen al umbral.
- **No consigue:** deshacer fichas o contribuciones ya entregadas, ni borrar copias.

## Modo discreto
`seal --discreet`: la cabecera no identifica a custodios, solicitantes ni candados, no nombra los grupos y el cuerpo se acolcha (como mínimo 4 KiB y como mucho un 12 % de más). Siguen visibles el emisor, el nivel, el número de grupos, miembros, umbrales, solicitantes y candados y el tamaño aproximado. El custodio prueba cada hueco con su clave. El solicitante no puede saber si está autorizado: lo comprueban custodios y guardián.

## Anclas y latidos
`--anchor` se puede repetir: para ocultar un recorte del diario habría que restaurar a la vez el diario y todas las anclas. Programa `guardian tick` y `custodian tick` (por ejemplo cada hora): una solicitud que caducó antes del último apunte se rechaza aunque alguien retrase el reloj.

## Modelo formal
[`../formal/qsel.spthy`](../formal/qsel.spthy) es un modelo **simbólico** en Tamarin (veredictos en `formal/expected_qsel.json`, se ejecutan con `python -m qce formal`). Para un grupo de dos custodios y un candado comprueba que leer exige el quórum, la clave de apertura o la firma del solicitante (la del emisor no basta); que un archivo con candado exige además la maestra o la ficha; y que romper las firmas no consigue una ficha. La variante `-DUNBOUND` reproduce el ataque contra el formato 3. **No** modela umbrales parciales, diarios, modo discreto ni el código, y supone primitivas ideales.

## Límites declarados
- Quien **abre** (o **rota**) reconstruye la clave y ve el texto claro: es un punto único de confianza en ese momento.
- La revocación no es retroactiva: fichas y contribuciones ya entregadas siguen valiendo, y las copias antiguas no se borran. Sin candado depende de que haya suficientes custodios honrados que retiren el archivo. No hay secreto hacia adelante, y la destrucción de una maestra no se puede demostrar sin hardware especial.
- La cabecera normal revela huellas, nombres de grupo, umbrales, solicitantes e identificadores de candado; la discreta, solo lo dicho arriba.
- Diario: sin ancla en otro medio, cortar el final no se detecta; quien restaure a la vez el diario y todas las anclas lo consigue. Un reloj retrasado revive las solicitudes que caducaron **después** del último apunte (los latidos acortan esa ventana).
- Quien pueda firmar como un solicitante autorizado puede pedir las participaciones de un archivo **sin** candado y leerlo. Quien además tenga su secreto de alta puede obtener fichas.
- El emisor ve el texto claro y define la política; logrando que el guardián registre un archivo falso obtiene fichas para él.
- Los archivos de formato 3 siguen permitiendo trasladar sus participaciones a otra política a quien pueda firmar como el emisor: vuelve a sellarlos.
- Las frases elegidas a mano se pueden probar sin conexión (usa `--generate-passphrase`); Python no es de tiempo constante ni borra secretos.
- X-Wing es un **borrador** de la IETF; el nivel «high» usa el combinador propio de QCE. No es interoperable con age, HPKE ni otras herramientas.
- El segundo lector (`tests/sealed_reader.py`) y el modelo formal los escribió el mismo autor que el código: detectan divergencias, no errores de concepto compartidos.

## Antecedentes (no se afirma novedad)
El quórum sobre sobres cifrados ya existe (p. ej. el complemento `age-plugin-sss` para `age`, que además tiene un destinatario híbrido poscuántico); también existen las claves precompartidas contra ordenadores cuánticos (RFC 8784), el borrado de claves para hacer datos irrecuperables (Perlman, *The Ephemerizer*) y los diarios de transparencia para descifrados. No se hizo búsqueda de patentes.
