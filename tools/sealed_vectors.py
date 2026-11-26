"""Genera los vectores del sobre sellado en tests/sealed_vectors/. El sellado usa aleatoriedad fresca (ML-KEM no admite fijarla), así que volver a ejecutarlo
produce archivos DISTINTOS: los publicados son los guardados y las pruebas no los regeneran.  Uso: python tools/sealed_vectors.py"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qce.pqc.hybrid import LEVELS, HybridSigPrivateKey  # noqa: E402
from qce.sealed import envelope  # noqa: E402
from tests.sealed_vector_cases import CASES, ISSUED, derive, kem_seed_length, plaintext, short  # noqa: E402

OUT = ROOT / "tests" / "sealed_vectors"


def main() -> None:
    OUT.mkdir(exist_ok=True)
    manifest = []
    for c in CASES:
        name, level, suite = c["name"], LEVELS[c["level"]], envelope.SUITES[c["level"]]
        n_kem = kem_seed_length(c["level"])
        sender = HybridSigPrivateKey.from_seed(derive(name, "emisor", 64), level)
        requester = HybridSigPrivateKey.from_seed(derive(name, "solicitante", 64), level)
        opener = suite.from_seed(derive(name, "apertura", n_kem))
        cust = {(g, x): suite.from_seed(derive(name, f"custodio-{g}-{x}", n_kem)) for g, (_, _, n) in enumerate(c["groups"], 1) for x in range(1, n + 1)}
        groups = [envelope.Group(gn, k, tuple(cust[(g, x)].public_bytes for x in range(1, n + 1))) for g, (gn, k, n) in enumerate(c["groups"], 1)]
        locks = [envelope.Lock(derive(name, f"candado-id-{label}", 16), label, derive(name, f"candado-{label}", 32)) for label in c["locks"]]
        out = OUT / f"{name}.qsel"
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "claro"
            src.write_bytes(plaintext(c["plain_len"]))
            hd = envelope.seal(src, out, sender, groups, [requester.public_bytes], c["need"], c["aead"], locks)
        (OUT / f"{name}.stub").write_bytes(envelope.make_stub(out, sender.public_bytes))
        request = envelope.request_open(out, sender.public_bytes, requester, opener.public_bytes, "vector de prueba", 3600, ISSUED)
        (OUT / f"{name}.req.msg").write_bytes(request)
        shares = {}
        for g, x in c["quorum"]:
            part = envelope.contribute(out, sender.public_bytes, cust[(g, x)], request, now=ISSUED)
            (OUT / f"{name}.{g}-{x}.msg").write_bytes(part)
            gg, xx, share = envelope._check_contribution(hd, part, opener)
            shares[(gg, xx)] = share
        secret = envelope.recover_secret(hd, shares)
        sid = bytes.fromhex(hd.data["sid"])
        file_keys = tuple(k.file_key(sid) for k in locks)
        manifest.append({"name": name, "digests": {
            "header": short(hd.digest), "secret": short(secret), "payload_key": short(envelope._payload_key(secret, hd.digest, file_keys)),
            "request_id": short(envelope.read_request(hd, request, ISSUED).ident), "shares": {f"{g},{x}": short(s) for (g, x), s in sorted(shares.items())},
            "lock_file_keys": [short(k) for k in file_keys]}})
        print(name, out.stat().st_size, "bytes")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
