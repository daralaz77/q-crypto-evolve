# Panel local de solo lectura

Un tablero para ver el estado del proyecto sin leer JSON: puertas G1–G6, si siguen vigentes para el código actual, incidentes, cadena de hashes, firmas y tiempos.

```bash
python panel/server.py            # http://127.0.0.1:8765
python panel/server.py --port 9000
```

**Solo lectura, a propósito.** Escucha únicamente en `127.0.0.1`; acepta solo GET/HEAD; valida la cabecera `Host`; CSP estricta (sin scripts ni estilos en línea); no ejecuta comandos, no escribe archivos y no lee claves privadas. No verifica firmas (eso lo hace la puerta G6): muestra qué firmas existen y si son de este código.

El panel nunca es «más verde» que el informe: solo muestra «aprobado» si `gates_latest.json` dice `RELEASE_APPROVED` y todas las puertas pasan. Con G5 omitida muestra «requiere revisión humana».

**Fuera de las puertas.** Vive en `panel/`, que no entra en el hash del `release_id`, así que no invalida firmas. Por lo mismo, sus pruebas se ejecutan aparte (también en CI):

```bash
python -m pytest panel/tests -o addopts= -q
```

Esas pruebas comparan el panel con el propio `qce` (mismos incidentes, mismo `release_id`, misma cadena) para que no diverjan en silencio.

**Animaciones.** Respetan «reducir movimiento» del sistema; el botón «Animaciones» permite cambiarlo a mano.
