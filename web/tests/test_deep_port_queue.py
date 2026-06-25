"""Deep-tier UDP scan queue isolation.

The multi-day UDP sweep must run on a DEDICATED queue/worker so it never holds a
``main_scan_queue`` slot (the deadlock the PR #33 queue isolation prevents), and
the celery container must actually start a consumer for that queue — otherwise
dispatched ``udp_port_scan`` tasks would queue forever with nothing to run them.

Run with:  python3 manage.py test tests.test_deep_port_queue
"""
import os
import unittest

from Suricatoos.tasks import udp_port_scan, port_scan


class DeepPortQueueRoutingTests(unittest.TestCase):
    def test_udp_task_routed_to_dedicated_queue(self):
        self.assertEqual(udp_port_scan.queue, 'deep_port_queue')

    def test_tcp_port_scan_stays_on_main_queue(self):
        # The fast/medium TCP path is unchanged: still the memory-bounded main queue.
        self.assertEqual(port_scan.queue, 'main_scan_queue')

    def test_udp_task_has_multi_day_limits(self):
        # The per-task limits override the global 2h CELERY hard limit (belt-and-
        # suspenders; the run_command watchdog is the real bound on the gevent pool).
        self.assertGreater(udp_port_scan.time_limit, 7 * 24 * 3600)
        self.assertGreater(udp_port_scan.soft_time_limit, 7 * 24 * 3600)
        self.assertLess(udp_port_scan.soft_time_limit, udp_port_scan.time_limit)


class DeepPortWorkerEntrypointTests(unittest.TestCase):
    def test_entrypoint_starts_a_deep_port_worker(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')
        with open(path) as f:
            content = f.read()
        self.assertIn('deep_port_queue', content)
        self.assertIn('deep_port_worker', content)


if __name__ == '__main__':
    unittest.main()
