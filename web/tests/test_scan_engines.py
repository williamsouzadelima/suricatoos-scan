"""The 3 depth-tier engines (Fast/Medium/Deep) load from the fixture with the expected
depth_tier and port scope."""
import yaml
from django.test import TestCase
from django.core.management import call_command
from scanEngine.models import EngineType


class DepthTierEngineTests(TestCase):
    def setUp(self):
        # match the entrypoint's invocation: load by PATH (the fixture lives in the
        # project-level fixtures/ dir, not in scanEngine/fixtures/).
        call_command('loaddata', 'fixtures/default_scan_engines.yaml', verbosity=0)

    def test_three_depth_engines_loaded(self):
        names = set(EngineType.objects.values_list('engine_name', flat=True))
        self.assertTrue({'Fast Scan', 'Medium Scan', 'Deep Scan'} <= names)

    def test_depth_tier_and_ports_per_engine(self):
        cases = {
            'Fast Scan': ('fast', ['top-100']),
            'Medium Scan': ('medium', ['top-1000']),
            'Deep Scan': ('deep', ['full']),
        }
        for name, (tier, ports) in cases.items():
            cfg = yaml.safe_load(EngineType.objects.get(engine_name=name).yaml_configuration)
            self.assertEqual(cfg['depth_tier'], tier)
            self.assertEqual(cfg['port_scan']['ports'], ports)

    def test_deep_enables_udp_full(self):
        cfg = yaml.safe_load(EngineType.objects.get(engine_name='Deep Scan').yaml_configuration)
        self.assertTrue(cfg['port_scan'].get('udp'))
        self.assertEqual(cfg['port_scan']['ports'], ['full'])

    def test_fast_is_lightweight(self):
        cfg = yaml.safe_load(EngineType.objects.get(engine_name='Fast Scan').yaml_configuration)
        # fast skips the heavy stages
        self.assertNotIn('dir_file_fuzz', cfg)
        self.assertNotIn('osint', cfg)
        self.assertNotIn('amass-active', cfg['subdomain_discovery']['uses_tools'])
