"""Emite el certificado de laboratorio para la clave PÚBLICA exportada del token (la privada nunca sale). Uso: python docs/hsm_lab/issue_cert.py <carpeta del laboratorio> (desde la raíz del proyecto)."""
import datetime as dt
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, ".")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from qce.transport import pki  # noqa: E402

lab = Path(sys.argv[1])
(lab / "ca").mkdir(exist_ok=True)
ca_path, ca_key, ca_cert = pki.issue_ca(lab / "ca", "QCE HSM lab CA", days=365)
pub = serialization.load_pem_public_key((lab / "tls-pub.pem").read_bytes())
now = dt.datetime.now(dt.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_cert.subject).public_key(pub)
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
(lab / "tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print("certificado emitido:", lab / "tls.pem", "· CA:", ca_path)
