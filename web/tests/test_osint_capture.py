import datetime

from django.test import TestCase
from django.utils import timezone
from startScan.models import OsintResult, ScanHistory
from scanEngine.models import EngineType
from Suricatoos.tasks import save_osint_result
from targetApp.models import Domain


class OsintSchemaTests(TestCase):
    def test_new_fields_exist(self):
        o = OsintResult.objects.create(event_type='X', data='d', module='sfp_dnsraw',
                                       parent='delphos.com.br', confidence=80)
        o.refresh_from_db()
        self.assertEqual((o.module, o.parent, o.confidence), ('sfp_dnsraw', 'delphos.com.br', 80))

    def test_bucket_org_choice(self):
        self.assertIn(OsintResult.BUCKET_ORG, dict(OsintResult.BUCKET_CHOICES))


class SaveOsintResultTests(TestCase):
    def setUp(self):
        d = Domain.objects.create(name='delphos.com.br')
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(domain=d, scan_type=engine, start_scan_date=timezone.now())

    def test_persists_module_parent_confidence(self):
        obj, _ = save_osint_result(self.scan, OsintResult.BUCKET_INFRA_DNS, 'DNS TXT Record',
                                   'v=spf1', module='sfp_dnsraw', parent='delphos.com.br',
                                   confidence=90)
        self.assertEqual((obj.module, obj.parent, obj.confidence), ('sfp_dnsraw', 'delphos.com.br', 90))

    def test_generated_sets_discovered_date(self):
        ts = 1781925945
        obj, _ = save_osint_result(self.scan, OsintResult.BUCKET_INFRA_DNS, 'X', 'd', generated=ts)
        self.assertEqual(obj.discovered_date,
                         datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc))
