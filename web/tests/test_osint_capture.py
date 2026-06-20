from django.test import TestCase
from startScan.models import OsintResult


class OsintSchemaTests(TestCase):
    def test_new_fields_exist(self):
        o = OsintResult.objects.create(event_type='X', data='d', module='sfp_dnsraw',
                                       parent='delphos.com.br', confidence=80)
        o.refresh_from_db()
        self.assertEqual((o.module, o.parent, o.confidence), ('sfp_dnsraw', 'delphos.com.br', 80))

    def test_bucket_org_choice(self):
        self.assertIn(OsintResult.BUCKET_ORG, dict(OsintResult.BUCKET_CHOICES))
