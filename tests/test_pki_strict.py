"""La PKI de laboratorio debe cumplir la RFC 5280 que los clientes ESTRICTOS exigen (INC-0032).

`requests` y el contexto por defecto de Python ≥ 3.13 activan `VERIFY_X509_STRICT` y rechazaban nuestros certificados con «Missing Authority Key Identifier»; `curl` y los contextos
no estrictos que usaban nuestras pruebas los aceptaban, y por eso nadie lo vio hasta contrastar con una herramienta externa (la sonda de conformidad de qkdsec).
"""
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qce.transport import pki


def strict_client(ca):
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT       # explícito: en Python < 3.13 no es el valor por defecto
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def handshake(server_ctx, client_ctx, host="127.0.0.1"):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    err = []

    def serve():
        raw, _ = ls.accept()
        try:
            with server_ctx.wrap_socket(raw, server_side=True) as s:
                s.sendall(s.recv(4)[::-1])
        except (ssl.SSLError, OSError) as exc:
            err.append(exc)
    t = threading.Thread(target=serve)
    t.start()
    try:
        with client_ctx.wrap_socket(socket.create_connection(("127.0.0.1", ls.getsockname()[1]), timeout=5), server_hostname=host) as c:
            c.sendall(b"ping")
            out = c.recv(4)
    except ssl.SSLError as exc:
        out = exc
    t.join(5)
    ls.close()
    return out


def server_ctx(cert, key):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.load_cert_chain(str(cert), str(key))
    return c


def test_a_strict_client_accepts_the_lab_server_certificate_by_ip_and_by_name(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    cert, key = pki.issue_leaf(tmp_path, ck, cc, "kme.lab", server=True)
    assert handshake(server_ctx(cert, key), strict_client(ca)) == b"gnip"                    # por la IP 127.0.0.1 del SAN
    assert handshake(server_ctx(cert, key), strict_client(ca), host="kme.lab") == b"gnip"    # y por el nombre DNS


def test_every_certificate_and_the_crl_carry_the_key_identifiers_the_rfc_requires(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    leaf_pem, _ = pki.issue_leaf(tmp_path, ck, cc, "x", server=False)
    leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
    ca_ski = cc.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    leaf_aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert leaf_aki.key_identifier == ca_ski.digest                                         # el AKI de la hoja apunta al SKI de la CA
    assert leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest != ca_ski.digest
    crl = x509.load_pem_x509_crl(pki.issue_crl(tmp_path, ck, cc, [leaf]).read_bytes())
    assert crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == ca_ski.digest


def test_a_certificate_signed_from_a_csr_is_also_strictly_valid(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.lab")]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("csr.lab")]), critical=False).sign(key, hashes.SHA256()))
    cert = pki.sign_csr(ck, cc, csr)
    assert cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == \
        cc.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "c.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    assert handshake(server_ctx(tmp_path / "c.pem", tmp_path / "c.key"), strict_client(ca), host="csr.lab") == b"gnip"
