"""import_openvas_findings — resiliência e contagem (auditoria 2026-07-04, wave 1).

Cobre o fix HIGH: um achado com cvss não-numérico NÃO derruba o lote inteiro (antes,
`float('n/a')` estourava, deixava rows parciais, travava o job e os achados reais
expiravam), e a contagem retornada é DISTINTA (achados que casam a mesma chave = 1 vuln).

Run with:  python3 manage.py test tests.test_openvas_import
"""
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from targetApp.models import Domain
from startScan.models import ScanHistory, EngineType, Subdomain, IpAddress, Vulnerability
from Suricatoos.tasks import import_openvas_findings


class ImportOpenvasFindingsTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.project = Project.objects.create(name="t", slug="t", insert_date=now)
        self.domain = Domain.objects.create(name="ex.com", project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name="e", yaml_configuration="", default_engine=False)
        self.scan = ScanHistory.objects.create(
            start_scan_date=now, domain=self.domain, scan_type=self.engine, scan_status=2)
        # host 1.2.3.4 em escopo (mapeia p/ um Subdomain); 9.9.9.9 fora de escopo.
        sub = Subdomain.objects.create(scan_history=self.scan, name="h.ex.com", target_domain=self.domain)
        ip = IpAddress.objects.create(address="1.2.3.4")
        sub.ip_addresses.add(ip)

    def test_bad_cvss_does_not_abort_batch(self):
        findings = [
            {"host": "1.2.3.4", "oid": "o1", "port": "443", "name": "A", "cvss_base": "7.5"},
            {"host": "1.2.3.4", "oid": "o2", "port": "80", "name": "B", "cvss_base": "n/a"},  # tóxico p/ o bug antigo
            {"host": "1.2.3.4", "oid": "o3", "port": "22", "name": "C", "cvss_base": "9.8"},
        ]
        n = import_openvas_findings(self.scan, findings)  # NÃO pode estourar
        self.assertEqual(n, 3)
        self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan).count(), 3)
        # o achado com cvss 'n/a' foi importado, com cvss_score nulo (não numérico) e severidade 0.
        v = Vulnerability.objects.get(scan_history=self.scan, type="o2")
        self.assertIsNone(v.cvss_score)
        self.assertEqual(v.severity, 0)

    def test_distinct_count_not_inflated_by_duplicates(self):
        findings = [
            {"host": "1.2.3.4", "oid": "o1", "port": "443", "name": "A", "cvss_base": "7.5"},
            {"host": "1.2.3.4", "oid": "o1", "port": "443", "name": "A", "cvss_base": "7.5"},  # mesma chave
        ]
        n = import_openvas_findings(self.scan, findings)
        self.assertEqual(n, 1)
        self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan).count(), 1)

    def test_out_of_scope_host_quarantined(self):
        findings = [
            {"host": "9.9.9.9", "oid": "o1", "port": "443", "name": "evil", "cvss_base": "9.8"},
            {"host": "1.2.3.4", "oid": "o2", "port": "80", "name": "ok", "cvss_base": "5.0"},
        ]
        n = import_openvas_findings(self.scan, findings)
        self.assertEqual(n, 1)  # só o host em escopo
        self.assertFalse(Vulnerability.objects.filter(scan_history=self.scan, type="o1").exists())


if __name__ == "__main__":
    import unittest
    unittest.main()
