"""Escenario de QIL1: dos hilos escriben (y luego leen) a la vez en la misma `Layer`, en un PROCESO NUEVO (importa tls13 primero; ver tests/tls_scenarios.py).
Uso: python tests/layer_lock_scenarios.py  →  imprime un JSON (última línea).

El espía fuerza el cruce: cada hilo espera en una barrera DENTRO de `encrypt`, justo donde el contador-nonce ya se leyó y aún no se incrementó.
Sin candado, los dos hilos cifran con el mismo nonce; con candado, el segundo espera fuera y la barrera se rompe por plazo (se ignora)."""
import json
import socket
import threading

from qce.transport import qkd_layer as Q  # noqa: E402  (importa tls13 primero)


class Spy:
    def __init__(self, real):
        self.real, self.barrier, self.nonces = real, threading.Barrier(2), []

    def _meet(self, nonce):
        try:
            self.barrier.wait(0.5)
        except threading.BrokenBarrierError:
            pass
        self.nonces.append(int.from_bytes(nonce, "big"))

    def encrypt(self, nonce, data, aad):
        self._meet(nonce)
        return self.real.encrypt(nonce, data, aad)

    def decrypt(self, nonce, data, aad):
        self._meet(nonce)
        return self.real.decrypt(nonce, data, aad)


def concurrently(fn, n=2):
    out = []

    def run():
        try:
            out.append(fn())
        except Exception as exc:  # noqa: BLE001
            out.append(type(exc).__name__)
    ts = [threading.Thread(target=run) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    return sorted(out)


def main():
    a, b = socket.socketpair()
    key, th = bytes(range(32)), b"t" * 32
    writer, reader = Q.Layer(a, key, bytes(32), th), Q.Layer(b, bytes(32), key, th)
    spy = writer._send = Spy(writer._send)
    threads = [threading.Thread(target=writer.write, args=(m,)) for m in (b"uno", b"dos")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    b.settimeout(3)
    rspy = reader._recv = Spy(reader._recv)
    got = concurrently(lambda: reader.read().decode())   # dos hilos leen a la vez: sin candado de lectura comparten el contador y el marco
    print(json.dumps({"nonces": sorted(spy.nonces), "read": got, "read_nonces": sorted(rspy.nonces)}))


main()
