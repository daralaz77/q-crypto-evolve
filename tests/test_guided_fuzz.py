"""Ítem 1.3 de la Fase 1: fuzzing guiado por cobertura de los parsers y del apretón. 0 caídas en un presupuesto FIJO, más canarios que prueban que el fuzzer SÍ encuentra fallos."""
import inspect
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
pytestmark = pytest.mark.skipif(not hasattr(sys, "monitoring"), reason="sys.monitoring requiere Python >= 3.12")

from guided_fuzz import GuidedFuzzer  # noqa: E402

from qce.core import encoding  # noqa: E402
from qce.core.encoding import pack  # noqa: E402
from qce.core.errors import QCEError  # noqa: E402
from qce.pqc.hybrid import HybridSigPrivateKey  # noqa: E402
from qce.protocols.session import ClientHandshake, ServerHandshake  # noqa: E402

QCE = str(Path(encoding.__file__).resolve().parent.parent)


def watch_qce(path: str) -> bool:
    return path.startswith(QCE) or path.startswith("<mutant")


@pytest.fixture(scope="module")
def ident():
    return HybridSigPrivateKey.generate()


def test_the_parser_survives_guided_fuzzing_with_zero_crashes_and_finds_new_code():
    seeds = [pack(1, [b"a", b"bc"]), pack(3, [b"x" * 40]), pack(2, [b"", b"", b""]), b"\x01\x02"]
    f = GuidedFuzzer(lambda d: [encoding.unpack(d, k, c) for k in (1, 2, 3) for c in (0, 1, 2, 3)], seeds, (QCE_ERR := QCEError,), watch_qce, rng_seed=7)
    rep = f.run(iterations=6000)
    assert rep["crashes"] == 0, rep["first_crash"]
    assert rep["new_lines_beyond_seeds"] > 0 and rep["corpus"] >= len(seeds)  # la guía descubrió código que las semillas no tocaban


def test_the_server_hello_handler_survives_guided_fuzzing(ident):
    c = ClientHandshake(ident.public_bytes)
    seed_hello = c.start()

    def target(data: bytes):
        ServerHandshake(ident).on_client_hello(data)  # un servidor NUEVO por entrada: sin estado compartido
    f = GuidedFuzzer(target, [seed_hello, pack(1, [b"QCE1", b"\0" * 32, b"X", b""])], (QCEError,), watch_qce, rng_seed=11)
    rep = f.run(iterations=1500)
    assert rep["crashes"] == 0, rep["first_crash"]


def _mutant(src_marker: str, replacement: str):
    """`unpack` con UN control quitado (compilado aparte para que la cobertura lo vea)."""
    src = inspect.getsource(encoding.unpack)
    assert src_marker in src, "el fragmento a mutar ya no está: actualice el canario"
    ns = {"struct": encoding.struct, "MalformedMessage": encoding.MalformedMessage, "MAX_FIELD": encoding.MAX_FIELD}
    exec(compile(src.replace(src_marker, replacement), "<mutant>", "exec"), ns)
    return ns["unpack"]


@pytest.mark.parametrize("marker,replacement,name", [
    ('    if len(data) < 2:\n        raise MalformedMessage("mensaje truncado")\n', "", "sin comprobar el mensaje truncado"),
    ('        if pos + 4 > len(data):\n            raise MalformedMessage("longitud truncada")\n', "", "sin comprobar la longitud truncada"),
])
def test_canary_a_parser_with_a_check_removed_is_caught_by_the_fuzzer(marker, replacement, name):
    mutant = _mutant(marker, replacement)
    seeds = [pack(1, [b"a", b"bc"]), b"\x01\x02"]
    f = GuidedFuzzer(lambda d: mutant(d, 1, 2), seeds, (QCEError,), watch_qce, rng_seed=3)
    rep = f.run(iterations=4000)
    assert rep["crashes"] >= 1, f"el fuzzer NO vio el control quitado ({name}): no sirve como red de seguridad"
    assert rep["first_crash"][1] in ("error", "IndexError", "TypeError")  # struct.error se llama «error»


def _gated(data: bytes):
    """Fallo escondido tras TRES condiciones consecutivas (la probabilidad de acertarlas al azar es ~2⁻²⁴ por entrada)."""
    if len(data) > 3 and data[0] == 0x51:
        if data[1] == 0x43:
            if data[2] == 0x45:
                raise ZeroDivisionError("fallo escondido")
    raise QCEError("rechazado")


def test_canary_guidance_finds_a_gated_bug_that_blind_mutation_does_not():
    here = str(Path(__file__).resolve())
    watch_here = lambda p: p == here  # noqa: E731
    seeds = [b"\x00\x00\x00\x00", b"\x51\x00\x00\x00"]
    guided = GuidedFuzzer(_gated, seeds, (QCEError,), watch_here, rng_seed=5, guided=True).run(iterations=20000)
    blind = GuidedFuzzer(_gated, seeds, (QCEError,), watch_here, rng_seed=5, guided=False).run(iterations=20000)
    assert guided["crashes"] >= 1, "la guía por cobertura no encontró el fallo escondido"
    assert blind["crashes"] == 0, "sin guía el fallo se encontró igualmente: el canario no demuestra la ventaja de la cobertura"
