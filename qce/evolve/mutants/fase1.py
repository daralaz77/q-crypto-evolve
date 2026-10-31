"""Mutantes de los controles de la Fase 1 (ratelimit, vault/EpochAnchor, workflow firmado, destrucción de la clave KEM, rotación). Cada uno rompe UNA garantía."""
from ._base import Mutant as M

HY, SE, VA, WF, RL, TL, QL, RO = ("qce/pqc/hybrid.py", "qce/protocols/session.py", "qce/key_management/vault.py", "qce/evolve/workflow.py",
                                  "qce/core/ratelimit.py", "qce/transport/tls13.py", "qce/transport/qkd_layer.py", "qce/transport/rotation.py")

MUTANTS = [
    # --- 1.7 descarte observable de la clave KEM efímera ---
    M("kem-destroy-noop", HY, (("        self._x = self._m = None\n", "        pass\n"),), "clave KEM efímera: destroy() la suelta"),
    M("kem-decapsulate-after-destroy-allowed", HY, (('        if self._x is None or self._m is None:\n            raise AuthenticationFailure("clave KEM efímera ya descartada")\n        if len(ct)', '        if len(ct)'),), "clave KEM efímera: no desencapsula tras destruirse"),
    M("kem-seed-after-destroy-allowed", HY, (('        if self._x is None or self._m is None:\n            raise AuthenticationFailure("clave KEM efímera ya descartada")\n        from cryptography', '        from cryptography'),), "clave KEM efímera: no se exporta tras destruirse"),
    M("server-kem-destroy-skipped", SE, (("        finally:\n            kem.destroy()  # observable", "        finally:\n            pass  # observable"),), "servidor: destruye la clave KEM aunque el apretón falle"),
    # --- 1.5 ancla externa del epoch ---
    M("anchor-can-go-backwards", VA, (("            if epoch < self.read():\n                raise IntegrityError(\"el ancla de epoch no puede retroceder\")", "            if False:\n                raise IntegrityError(\"el ancla de epoch no puede retroceder\")"),), "ancla de epoch: monótona"),
    M("anchor-damaged-read-as-zero", VA, (('            raise IntegrityError("el ancla de epoch está dañada") from exc', "            return 0"),), "ancla de epoch: dañada no se toma por 0"),
    M("load-anchored-ignores-the-anchor", VA, (("min_epoch=anchor.read()", "min_epoch=0"),), "vault: rechaza copias antiguas con el ancla"),
    M("save-anchored-does-not-advance", VA, (("    save(store, path, passphrase, n)\n    anchor.advance(store.epoch)", "    save(store, path, passphrase, n)"),), "vault: el guardado adelanta el ancla"),
    M("anchor-file-world-readable", "qce/core/atomic.py", (("        os.fchmod(fd, mode)\n", "        os.fchmod(fd, 0o644)\n"),), "ancla de epoch y vault: archivo 0600 (el modo se fija en la escritura atómica)"),
    # --- 1.6 transiciones firmadas ---
    M("workflow-signature-not-required", WF, (("            if pub is None or not signature:", "            if False:"),), "workflow: exige firma de un actor registrado"),
    M("workflow-signature-not-verified", WF, (("                hybrid_verify(pub, transition_payload(head, task_id, cur, to, role, actor_id, evidence, blocking_findings), signature, CTX_TRANSITION)", "                pass"),), "workflow: verifica la firma"),
    M("workflow-payload-without-head", WF, (('"head": head, "task"', '"head": "", "task"'),), "workflow: la firma se liga a la cabeza del registro (sin repeticiones)"),
    M("workflow-payload-without-evidence", WF, (('"evidence": list(evidence or [])', '"evidence": []'),), "workflow: la firma cubre la evidencia"),
    M("workflow-payload-without-actor", WF, (('"role": role, "actor": actor_id,\n                       "evidence"', '"role": role,\n                       "evidence"'),), "workflow: la firma cubre al actor"),
    # --- 1.2 límite de tasa por origen ---
    M("ratelimit-never-denies", RL, (("            ok = tokens >= 1.0\n", "            ok = True\n"),), "límite de tasa: deniega al agotarse las fichas"),
    M("ratelimit-burst-unbounded", RL, (("            tokens = min(float(self.burst), tokens + max(0.0, now - last) * self.rate)\n", "            tokens = tokens + max(0.0, now - last) * self.rate\n"),), "límite de tasa: la ráfaga está acotada"),
    M("ratelimit-no-refill", RL, (("tokens + max(0.0, now - last) * self.rate", "tokens + 0.0"),), "límite de tasa: las fichas se reponen con el tiempo"),
    M("ratelimit-memory-unbounded", RL, (("            while len(self._buckets) > self.max_origins:", "            while False:"),), "límite de tasa: memoria acotada ante orígenes falsos"),
    M("ratelimit-shared-bucket", RL, (("            tokens, last = self._buckets.pop(origin, (float(self.burst), now))", "            tokens, last = self._buckets.pop('*', (float(self.burst), now)); origin = '*'"),), "límite de tasa: un origen no gasta las fichas de otro (cubo por origen)"),
    M("tls-server-limiter-not-applied", TL, (("            if self._limiter is not None and not self._limiter.allow(str(addr[0])):", "            if False:"),), "transporte: el límite se aplica antes del apretón"),
    M("qil1-limiter-not-applied", QL, (("        limiter.check(str(sock.getpeername()[0]))", "        pass"),), "QIL1: el límite se aplica antes de reservar claves"),
    # --- 1.4 planificador de rotación ---
    M("rotation-thread-never-starts", RO, (("        self._thread.start()\n        return self", "        return self"),), "rotación: el hilo arranca solo"),
    M("rotation-errors-propagate", RO, (("        except Exception as exc:  # noqa: BLE001\n            self.errors += 1", "        except KeyboardInterrupt as exc:  # noqa: BLE001\n            self.errors += 1"),), "rotación: un fallo no mata al planificador"),
    M("rotation-invalid-schedule-accepted", RO, (("        if check_interval_s <= 0 or renew_before_s < 0 or ttl_s <= renew_before_s:", "        if False:"),), "rotación: rechaza calendarios inválidos"),
    M("rotation-stop-does-not-stop", RO, (("        self._stop.set()\n        if self._thread is not None:", "        if self._thread is not None:"),), "rotación: stop() detiene el hilo"),
]
