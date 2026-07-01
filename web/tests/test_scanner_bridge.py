"""Loop reNgine→OpenVAS (ADR-0006): mapeamento puro do scanner_bridge.

Cobre as funções sem dependência de DB/rede:
* ``cvss_to_rengine`` — bandas CVSS 0–10 → severidade reNgine 0–4.
* ``is_public_ip`` — só IP-literais unicast públicos passam (dropa privado/
  loopback/link-local/multicast/reservado e hostnames).

Run with:  python3 manage.py test tests.test_scanner_bridge
"""
import unittest

from Suricatoos.scanner_bridge import cvss_to_rengine, is_public_ip


class CvssToRengineTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(cvss_to_rengine(9.8), 4)   # Critical
        self.assertEqual(cvss_to_rengine(9.0), 4)
        self.assertEqual(cvss_to_rengine(7.5), 3)   # High
        self.assertEqual(cvss_to_rengine(7.0), 3)
        self.assertEqual(cvss_to_rengine(5.0), 2)   # Medium
        self.assertEqual(cvss_to_rengine(4.0), 2)
        self.assertEqual(cvss_to_rengine(2.1), 1)   # Low
        self.assertEqual(cvss_to_rengine(0.1), 1)
        self.assertEqual(cvss_to_rengine(0.0), 0)   # Info/Log

    def test_bad_input_is_info(self):
        self.assertEqual(cvss_to_rengine(None), 0)
        self.assertEqual(cvss_to_rengine("n/a"), 0)
        self.assertEqual(cvss_to_rengine(""), 0)


class IsPublicIpTests(unittest.TestCase):
    def test_public_pass(self):
        for ip in ("203.0.113.10", "8.8.8.8", "2001:db8::1"):
            self.assertTrue(is_public_ip(ip), ip)

    def test_non_public_reject(self):
        for ip in (
            "10.0.0.5", "192.168.1.1", "172.16.0.1",  # RFC1918
            "127.0.0.1", "::1",                        # loopback
            "169.254.169.254", "169.254.1.1",          # link-local / metadata
            "224.0.0.1",                               # multicast
            "0.0.0.0",                                 # unspecified
            "fe80::1", "fc00::1",                      # IPv6 link-local / ULA
        ):
            self.assertFalse(is_public_ip(ip), ip)

    def test_hostname_and_garbage_reject(self):
        for bad in ("evil.com", "*.evil.com", "notanip", "", None, "1.2.3.4:80"):
            self.assertFalse(is_public_ip(bad), repr(bad))


if __name__ == "__main__":
    unittest.main()
