"""Regression: vulnerability counts must exclude validator-flagged false positives
(so the app's counts match the PDF report — no 247-vs-245 drift)."""
from django.test import TestCase
from django.utils import timezone

from targetApp.models import Domain
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability


class VulnCountExcludesFalsePositiveTests(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='example.com')
        engine = EngineType.objects.create(engine_name='t-engine', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, start_scan_date=timezone.now())
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=domain, name='example.com')
        # 3 real findings (default validation_status, NOT false_positive)
        for sev in (4, 2, 0):  # critical, medium, info
            Vulnerability.objects.create(
                scan_history=self.scan, subdomain=self.sub, name=f'real-{sev}', severity=sev)
        # 1 validator-flagged false positive (severity high=3)
        Vulnerability.objects.create(
            scan_history=self.scan, subdomain=self.sub, name='fp', severity=3,
            validation_status=Vulnerability.VALIDATION_FALSE_POSITIVE)

    def test_total_excludes_false_positive(self):
        # 4 rows in DB, 1 is FP -> count returns 3
        self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan).count(), 4)
        self.assertEqual(self.scan.get_vulnerability_count(), 3)

    def test_severity_breakdown_sums_to_total_and_drops_fp(self):
        s = self.scan
        parts = (s.get_unknown_vulnerability_count() + s.get_info_vulnerability_count()
                 + s.get_low_vulnerability_count() + s.get_medium_vulnerability_count()
                 + s.get_high_vulnerability_count() + s.get_critical_vulnerability_count())
        self.assertEqual(parts, s.get_vulnerability_count())
        self.assertEqual(parts, 3)
        # the only severity-3 row is the FP -> high count must be 0
        self.assertEqual(s.get_high_vulnerability_count(), 0)

    def test_subdomain_counts_exclude_false_positive(self):
        # subdomain-level counts feed the API serializer + report per-subdomain rows
        self.assertEqual(self.sub.get_total_vulnerability_count, 3)
        self.assertEqual(self.sub.get_vulnerabilities.count(), 3)
