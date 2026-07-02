"""Enrola o reNgine (score) como cliente mTLS 'launcher' do scanner (ADR-0006).

Gera uma chave + CSR, troca um token de bootstrap por um certificado assinado
pela CA de enrollment do control-plane, e grava crt/key/ca onde as settings
SURICATOOS_SCANNER_* esperam. O token DEVE ter sido mintado com
tenant=score-hub e policy=scan-requester (→ cert O=score-hub, OU=scan-requester).

Uso:
    python manage.py openvas_enroll --token <BOOTSTRAP_TOKEN>
    python manage.py openvas_enroll --token <TOKEN> --cn score-hub-2026 --out-dir /certs
"""

import datetime
import os

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Enrola o reNgine como cliente mTLS do scanner OpenVAS (ADR-0006)."

    def add_arguments(self, parser):
        parser.add_argument("--token", required=True, help="Token de bootstrap (tenant=score-hub, policy=scan-requester)")
        parser.add_argument("--url", default="", help="Endpoint de enroll (default: deriva de SURICATOOS_SCANNER_URL)")
        parser.add_argument("--cn", default="", help="CN do cert (default: score-hub-<data>)")
        parser.add_argument("--os", default="linux")
        parser.add_argument("--arch", default="amd64")
        parser.add_argument("--out-dir", default="", help="Diretório de saída (default: dir de SURICATOOS_SCANNER_CERT)")

    def handle(self, *args, **opts):
        cn = opts["cn"] or ("score-hub-" + datetime.date.today().strftime("%Y%m%d"))
        enroll_url = opts["url"] or self._derive_enroll_url()
        out_dir = opts["out_dir"] or os.path.dirname(settings.SURICATOOS_SCANNER_CERT) or "."
        os.makedirs(out_dir, exist_ok=True)

        # 1) chave + CSR (CN == agent_id; O/OU vêm do escopo do token no control-plane).
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        # 2) troca token+CSR por um cert assinado.
        self.stdout.write(f"enrolando {cn} em {enroll_url} …")
        try:
            resp = requests.post(
                enroll_url,
                json={"token": opts["token"], "csr": csr_pem, "agent_id": cn,
                      "os": opts["os"], "arch": opts["arch"]},
                timeout=30,
            )
        except requests.RequestException as e:
            raise CommandError(f"falha de rede no enroll: {e}")
        if resp.status_code >= 400:
            raise CommandError(f"enroll rejeitado ({resp.status_code}): {resp.text[:300]}")
        data = resp.json()
        if not data.get("certificate") or not data.get("ca_cert"):
            raise CommandError(f"resposta de enroll incompleta: {data}")

        # 3) grava crt/key/ca nos caminhos que as settings esperam.
        crt_path = self._path(out_dir, settings.SURICATOOS_SCANNER_CERT, "score-hub.crt")
        key_path = self._path(out_dir, settings.SURICATOOS_SCANNER_KEY, "score-hub.key")
        ca_path = self._path(out_dir, settings.SURICATOOS_SCANNER_CA, "score-hub.ca.crt")
        self._write(crt_path, data["certificate"], 0o644)
        self._write(key_path, key_pem, 0o600)
        self._write(ca_path, data["ca_cert"], 0o644)

        self.stdout.write(self.style.SUCCESS(f"OK — cert={crt_path} key={key_path} ca={ca_path}"))
        self.stdout.write("Monte este diretório em /certs (celery + celery-beat) e defina SURICATOOS_SCANNER_PUSH_ENABLED quando for a P4.")

    def _derive_enroll_url(self):
        # SURICATOOS_SCANNER_URL = https://host/ingest → enroll = https://host/agent/v1/enroll
        base = settings.SURICATOOS_SCANNER_URL.rstrip("/")
        if base.endswith("/ingest"):
            base = base[: -len("/ingest")]
        return base + "/agent/v1/enroll"

    @staticmethod
    def _path(out_dir, settings_path, fallback):
        return os.path.join(out_dir, os.path.basename(settings_path or fallback))

    @staticmethod
    def _write(path, content, mode):
        with open(path, "w") as f:
            f.write(content if content.endswith("\n") else content + "\n")
        os.chmod(path, mode)
