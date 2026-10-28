# Demo guiada

Una página estática (sin servidor, sin dependencias, sin peticiones externas) que explica en lenguaje normal cómo se entrega una clave en el laboratorio y cómo sus pruebas atrapan un fallo. **No simula nada: muestra trazas reales grabadas** de `examples/SALIDA_ESPERADA.txt` y `benchmarks/demo_latest.json`.

```bash
python site/build.py              # regenera site/trazas.js desde las trazas reales
python -m http.server -d site 8766   # http://127.0.0.1:8766
```

`site/tests` comprueba que `trazas.js` coincide con sus fuentes, que cada línea mostrada existe en la salida real y que la página no usa `innerHTML` ni recursos externos. Está etiquetada como SIMULACIÓN y repite lo que no demuestra.

Para publicarla (p. ej. GitHub Pages) hace falta decidirlo y activarlo a mano: no se publica sola. Las animaciones respetan «reducir movimiento» del sistema y tienen un botón para cambiarlo.
