"""Cliente mTLS + mapeamento do loop reNgine→OpenVAS (ADR-0006).

Empurra os hosts/portas vivos de uma ScanHistory para o scanner
(scanner.suricatoos.com/ingest) e traduz os achados OpenVAS que voltam para o
modelo Vulnerability do reNgine. As funções puras (is_public_ip, build_payload,
cvss_to_rengine, build_ip_subdomain_map) são testáveis sem rede nem gvmd.
"""

import ipaddress
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0.0"
SOURCE_OPENVAS = "openvas"


def _cfg():
    return {
        "url": getattr(settings, "SURICATOOS_SCANNER_URL", "").rstrip("/"),
        "cert": getattr(settings, "SURICATOOS_SCANNER_CERT", ""),
        "key": getattr(settings, "SURICATOOS_SCANNER_KEY", ""),
        "ca": getattr(settings, "SURICATOOS_SCANNER_CA", ""),
        "max_hosts": int(getattr(settings, "SURICATOOS_SCANNER_MAX_HOSTS", 256)),
    }


def is_configured():
    c = _cfg()
    return bool(c["url"] and c["cert"] and c["key"])


def is_public_ip(addr):
    """True apenas para IP-literais unicast públicos — dropa privado/loopback/
    link-local/multicast/reservado (o scanner é autoritativo, mas pré-filtramos
    para não enviar alvos obviamente fora de escopo)."""
    try:
        ip = ipaddress.ip_address((addr or "").strip())
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def build_payload(scan_history):
    """Constrói [{ip, ports}] dos hosts públicos + portas abertas de uma
    ScanHistory (ScanHistory → Subdomain → ip_addresses → ports)."""
    by_ip = {}
    for sub in scan_history.subdomain_set.all():
        for ipaddr in sub.ip_addresses.all():
            addr = (ipaddr.address or "").strip()
            if not is_public_ip(addr):
                continue
            canon = str(ipaddress.ip_address(addr))
            ports = by_ip.setdefault(canon, set())
            for port in ipaddr.ports.all():
                if 1 <= port.number <= 65535:
                    ports.add(port.number)
    hosts = [{"ip": ip, "ports": sorted(ports)} for ip, ports in by_ip.items() if ports]
    return hosts


def cvss_to_rengine(cvss):
    """CVSS 0–10 → severidade reNgine 0–4 (0=Info … 4=Critical). Espelha as
    bandas do gmp-bridge."""
    try:
        c = float(cvss)
    except (TypeError, ValueError):
        return 0
    if c >= 9.0:
        return 4
    if c >= 7.0:
        return 3
    if c >= 4.0:
        return 2
    if c > 0.0:
        return 1
    return 0


def build_ip_subdomain_map(scan_history):
    """{ip_canônico: Subdomain} para os hosts DESTA ScanHistory. Um achado cujo
    host não está aqui é fora de escopo → quarentena (nunca atribuído ao alvo)."""
    m = {}
    for sub in scan_history.subdomain_set.all():
        for ipaddr in sub.ip_addresses.all():
            try:
                canon = str(ipaddress.ip_address((ipaddr.address or "").strip()))
            except ValueError:
                continue
            m.setdefault(canon, sub)
    return m


def _session():
    c = _cfg()
    s = requests.Session()
    s.cert = (c["cert"], c["key"])
    s.verify = c["ca"] or True
    return s


def submit(scan_history_id, target, engagement, hosts, timeout=30):
    """POST do scan-request. Retorna o JSON de resposta {request_id, state, ...}."""
    c = _cfg()
    if not is_configured():
        raise RuntimeError("SURICATOOS_SCANNER_URL/CERT/KEY não configurados")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "rengine_scan_history_id": int(scan_history_id),
        "target": target or "",
        "engagement": engagement or "",
        "hosts": hosts,
    }
    resp = _session().post(c["url"] + "/v1/scan-request", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def poll(request_id, timeout=60):
    """GET do estado do job (+ findings quando COMPLETED)."""
    c = _cfg()
    resp = _session().get(c["url"] + "/v1/scan-request/" + str(request_id), timeout=timeout)
    resp.raise_for_status()
    return resp.json()
