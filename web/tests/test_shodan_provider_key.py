"""Tests for the Shodan key persisted into subfinder's provider-config.yaml.

The key is stored in a YAML file (not the DB), so these tests point
SUBFINDER_PROVIDER_CONFIG_PATH at a temp file via override_settings.
"""
import os
import shutil
import tempfile

import yaml
from django.test import TestCase, override_settings

from scanEngine.provider_keys import (
    set_shodan_key,
    get_shodan_key,
    is_shodan_configured,
    masked_shodan_key,
    SUBFINDER_UI_PROVIDERS,
    set_subfinder_key,
    get_subfinder_key,
    is_subfinder_key_set,
    subfinder_providers_status,
)


class ShodanProviderKeyTests(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, 'subfinder', 'provider-config.yaml')
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        # realistic provider-config: shodan empty, other providers present
        with open(self.path, 'w') as fh:
            fh.write('alienvault: []\nchaos: []\nshodan: []\nvirustotal: []\n')
        self.override = override_settings(SUBFINDER_PROVIDER_CONFIG_PATH=self.path)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_unset_by_default(self):
        self.assertIsNone(get_shodan_key())
        self.assertFalse(is_shodan_configured())
        self.assertIsNone(masked_shodan_key())

    def test_set_and_read_strips_whitespace(self):
        self.assertTrue(set_shodan_key('  ABC123key  '))
        self.assertEqual(get_shodan_key(), 'ABC123key')
        self.assertTrue(is_shodan_configured())

    def test_set_preserves_other_providers(self):
        set_shodan_key('XYZ')
        with open(self.path) as fh:
            data = yaml.safe_load(fh)
        self.assertEqual(data['shodan'], ['XYZ'])
        self.assertIn('alienvault', data)
        self.assertIn('virustotal', data)
        self.assertEqual(data['chaos'], [])

    def test_replace_existing_key(self):
        set_shodan_key('first')
        set_shodan_key('second')
        self.assertEqual(get_shodan_key(), 'second')
        # exactly one shodan line — no duplicates appended
        with open(self.path) as fh:
            lines = [l for l in fh if l.startswith('shodan:')]
        self.assertEqual(len(lines), 1)

    def test_empty_key_is_noop(self):
        self.assertFalse(set_shodan_key('   '))
        self.assertFalse(set_shodan_key(None))
        self.assertFalse(is_shodan_configured())

    def test_appends_shodan_line_when_absent(self):
        with open(self.path, 'w') as fh:
            fh.write('alienvault: []\nvirustotal: []\n')
        self.assertTrue(set_shodan_key('NEW'))
        self.assertEqual(get_shodan_key(), 'NEW')

    def test_creates_file_when_missing(self):
        missing = os.path.join(self.tmpdir, 'fresh', 'provider-config.yaml')
        with override_settings(SUBFINDER_PROVIDER_CONFIG_PATH=missing):
            self.assertTrue(set_shodan_key('CREATED'))
            self.assertEqual(get_shodan_key(), 'CREATED')

    def test_masked_does_not_reveal_full_key(self):
        full = 'jGJOhGbencyCuoksgNuvhTJC6BrUVzvC'
        set_shodan_key(full)
        masked = masked_shodan_key()
        self.assertIsNotNone(masked)
        self.assertNotEqual(masked, full)
        self.assertNotIn(full[4:-3], masked)  # middle is hidden
        self.assertTrue(masked.startswith('jGJO'))
        self.assertTrue(masked.endswith('zvC'))


class SubfinderProviderKeysTests(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, 'subfinder', 'provider-config.yaml')
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w') as fh:
            fh.write('github: []\nvirustotal: []\ncensys: []\nshodan: []\n')
        self.override = override_settings(SUBFINDER_PROVIDER_CONFIG_PATH=self.path)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_registry_keys_are_valid_provider_names(self):
        # every UI provider id must be a plain subfinder provider token
        import re
        for p in SUBFINDER_UI_PROVIDERS:
            self.assertRegex(p['key'], r'^[a-z0-9_]+$')
            self.assertTrue(p['label'])
            self.assertTrue(p['url'])

    def test_set_and_read_multiple_providers_independently(self):
        self.assertTrue(set_subfinder_key('github', 'ghp_abc'))
        self.assertTrue(set_subfinder_key('virustotal', 'vt_xyz'))
        self.assertEqual(get_subfinder_key('github'), 'ghp_abc')
        self.assertEqual(get_subfinder_key('virustotal'), 'vt_xyz')
        # untouched providers stay empty
        self.assertIsNone(get_subfinder_key('censys'))
        self.assertFalse(is_subfinder_key_set('shodan'))

    def test_censys_pair_value_round_trips(self):
        self.assertTrue(set_subfinder_key('censys', 'APIID:SECRET'))
        self.assertEqual(get_subfinder_key('censys'), 'APIID:SECRET')

    def test_rejects_invalid_provider_name(self):
        # guards against arbitrary YAML keys / injection from a bad provider name
        self.assertFalse(set_subfinder_key('bad name', 'x'))
        self.assertFalse(set_subfinder_key('a: b\nevil', 'x'))
        with open(self.path) as fh:
            self.assertNotIn('evil', fh.read())

    def test_status_reflects_configured_flag(self):
        set_subfinder_key('github', 'ghp_abc')
        status = {p['key']: p['is_set'] for p in subfinder_providers_status()}
        self.assertTrue(status['github'])
        self.assertFalse(status['virustotal'])
        # status covers exactly the registry
        self.assertEqual(set(status), {p['key'] for p in SUBFINDER_UI_PROVIDERS})

    def test_shodan_wrappers_delegate_to_generic(self):
        set_shodan_key('SHKEY')
        self.assertEqual(get_subfinder_key('shodan'), 'SHKEY')
        self.assertTrue(is_shodan_configured())
