import datetime
from unittest import mock

from django.test import TestCase
from django.utils import timezone
from startScan.models import OsintResult, ScanHistory
from scanEngine.models import EngineType
from Suricatoos.tasks import save_osint_result
from Suricatoos import tasks
from targetApp.models import Domain
from api.serializers import OsintResultSerializer


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


class SpiderfootRoutingTests(TestCase):
    def setUp(self):
        d = Domain.objects.create(name='delphos.com.br')
        engine = EngineType.objects.create(engine_name='test-sf', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(domain=d, scan_type=engine,
                                               start_scan_date=timezone.now())
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': d.id}

    def _run(self, events):
        with mock.patch.object(tasks, 'run_command'), \
             mock.patch('builtins.open', mock.mock_open(read_data='[]')), \
             mock.patch.object(tasks.json, 'load', return_value=events), \
             mock.patch.object(tasks, 'seed_spiderfoot_config', return_value=False):
            tasks.spiderfoot_scan({}, 'delphos.com.br', self.scan.id, 1, '/tmp', ctx=self.ctx)

    def test_company_name_routed_to_org_bucket(self):
        self._run([{'type': 'Company Name', 'data': 'Delphos SA',
                    'module': 'sfp_x', 'source': 'delphos.com.br', 'generated': 1781925945}])
        self.assertTrue(OsintResult.objects.filter(
            bucket=OsintResult.BUCKET_ORG, data='Delphos SA').exists())

    def test_linked_url_routed_to_endpoint(self):
        with mock.patch.object(tasks, 'save_endpoint') as se:
            self._run([{'type': 'Linked URL - Internal',
                        'data': 'https://delphos.com.br/admin', 'module': 'sfp_spider',
                        'source': 'delphos.com.br', 'generated': 1781925945}])
            se.assert_called()

    def test_provenance_flows_into_osint(self):
        self._run([{'type': 'DNS TXT Record', 'data': 'v=spf1', 'module': 'sfp_dnsraw',
                    'source': 'delphos.com.br', 'generated': 1781925945}])
        row = OsintResult.objects.get(event_type='DNS TXT Record')
        self.assertEqual((row.module, row.parent), ('sfp_dnsraw', 'delphos.com.br'))


class OsintSerializerTests(TestCase):
    def test_new_fields_serialized(self):
        o = OsintResult.objects.create(event_type='X', data='d', module='sfp_dnsraw',
                                       parent='delphos.com.br', confidence=70)
        out = OsintResultSerializer(o).data
        for f in ('module', 'parent', 'confidence'):
            self.assertIn(f, out)
        self.assertEqual(out['confidence'], 70)

