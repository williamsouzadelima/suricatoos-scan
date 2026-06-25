"""Deep-tier UDP port scan: command assembly + nmap XML open-port parsing.

These cover the pure helpers wired into ``port_scan`` for the Deep depth tier:

* ``build_udp_nmap_cmd`` — emits ``nmap -sU`` ONLY for the deep tier, refuses an
  unsafe host, and produces a command that passes the security validator.
* ``parse_nmap_xml_open_ports`` — pulls OPEN ports out of an nmap ``-oX`` dump and
  is best-effort (never raises) on a missing / malformed file.

Run with:  python3 manage.py test tests.test_port_scan_tiers
"""
import os
import tempfile
import unittest

from Suricatoos.tasks import build_udp_nmap_cmd, parse_nmap_xml_open_ports
from Suricatoos.common_func import is_valid_nmap_command


class BuildUdpNmapCmdTests(unittest.TestCase):
    def test_udp_cmd_only_for_deep(self):
        # Non-deep tiers must never emit a UDP sweep.
        self.assertIsNone(build_udp_nmap_cmd('host.example.com', 'fast'))
        self.assertIsNone(build_udp_nmap_cmd('host.example.com', 'medium'))
        self.assertIsNone(build_udp_nmap_cmd('host.example.com', None))
        self.assertIsNone(build_udp_nmap_cmd('host.example.com', 'bogus'))
        # Deep emits -sU over the full 65535 UDP range.
        cmd = build_udp_nmap_cmd('host.example.com', 'deep')
        self.assertIsNotNone(cmd)
        self.assertIn('-sU', cmd)
        self.assertIn('-p 1-65535', cmd)
        self.assertTrue(cmd.endswith('host.example.com'))

    def test_udp_cmd_quotes_host(self):
        # A shell-metachar host is rejected (cannot smuggle a command).
        self.assertIsNone(build_udp_nmap_cmd('host.com; rm -rf /', 'deep'))
        # A host posing as a flag (leading dash) is rejected.
        self.assertIsNone(build_udp_nmap_cmd('-oG/tmp/x', 'deep'))
        self.assertIsNone(build_udp_nmap_cmd('', 'deep'))
        # A normal host/IP is accepted and appears verbatim at the end.
        self.assertTrue(build_udp_nmap_cmd('10.0.0.5', 'deep').endswith('10.0.0.5'))

    def test_udp_cmd_passes_security_validator(self):
        # The assembled command (without the appended host) must pass the nmap
        # command allowlist — defense in depth against an output-file / injection flag.
        cmd = build_udp_nmap_cmd('host.example.com', 'deep', out_file='/usr/src/results/h.xml', max_rate=500)
        self.assertIsNotNone(cmd)
        self.assertIn('-oX /usr/src/results/h.xml', cmd)
        self.assertIn('--max-rate 500', cmd)
        # Strip the trailing host and confirm the flag portion validates.
        flag_part = cmd.rsplit(' ', 1)[0]
        self.assertTrue(is_valid_nmap_command(flag_part))

    def test_udp_cmd_bad_rate_is_dropped(self):
        cmd = build_udp_nmap_cmd('host.example.com', 'deep', max_rate='not-a-number')
        self.assertIsNotNone(cmd)
        self.assertNotIn('--max-rate', cmd)


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="host.example.com" type="user"/></hostnames>
    <ports>
      <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
      <port protocol="udp" portid="123"><state state="open"/><service name="ntp"/></port>
      <port protocol="udp" portid="500"><state state="closed"/><service name="isakmp"/></port>
      <port protocol="udp" portid="161"><state state="open|filtered"/></port>
    </ports>
  </host>
</nmaprun>
"""


class ParseNmapXmlOpenPortsTests(unittest.TestCase):
    def test_parses_only_open_ports(self):
        fd, path = tempfile.mkstemp(suffix='.xml')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(SAMPLE_NMAP_XML)
            results = parse_nmap_xml_open_ports(path)
        finally:
            os.unlink(path)
        open_numbers = sorted(r['port'] for r in results)
        # 53 + 123 are open; 500 closed and 161 open|filtered are excluded.
        self.assertEqual(open_numbers, [53, 123])
        by_port = {r['port']: r for r in results}
        self.assertEqual(by_port[53]['service'], 'domain')
        self.assertEqual(by_port[53]['ip'], '10.0.0.5')
        self.assertEqual(by_port[53]['host'], 'host.example.com')
        self.assertEqual(by_port[53]['protocol'], 'udp')

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_nmap_xml_open_ports('/nonexistent/path/none.xml'), [])

    def test_malformed_file_returns_empty(self):
        fd, path = tempfile.mkstemp(suffix='.xml')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write('this is not xml <<<')
            self.assertEqual(parse_nmap_xml_open_ports(path), [])
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
