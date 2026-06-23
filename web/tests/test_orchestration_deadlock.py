"""Regression tests for the multi-tenant scan-orchestration deadlock fix.

Background (scan-#28 hang): a fan-out scan task (vulnerability_scan / nuclei_scan /
port_scan) would dispatch a Celery group/chord and then block UNBOUNDED waiting for
its children. On the 4-slot prefork ``main_scan_queue`` the blocked parents held the
slots their own children needed -> deadlock for every user. Compounding it,
``stream_command``'s readline loop never saw EOF when a watchdog-killed tool left a
grandchild holding the stdout pipe, wedging the worker forever with a zombie.

These tests cover the four defenses:
  1. join_group_with_timeout  -> bounded barrier + revoke-on-timeout (C1)
  2. _read_lines_until_dead    -> interruptible read so a killed tool can't wedge it
  3. queue routing             -> coordinators isolated off main_scan_queue (C2)
  4. hang_monitor              -> periodic backstop that auto-aborts wedged scans

Run with:  python3 manage.py test tests.test_orchestration_deadlock
"""
import unittest
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.utils import timezone
from datetime import timedelta

from Suricatoos.tasks import (
    join_group_with_timeout, _read_lines_until_dead, hang_monitor,
    vulnerability_scan, nuclei_scan, nmap, nuclei_individual_severity_module,
    dalfox_xss_scan, crlfuzz_scan, s3scanner,
)
from Suricatoos.definitions import RUNNING_TASK, ABORTED_TASK, SUCCESS_TASK


# --------------------------------------------------------------------------- #
# 1. join_group_with_timeout — bounded orchestration barrier                  #
# --------------------------------------------------------------------------- #
class JoinGroupWithTimeoutTests(unittest.TestCase):
    def _job(self, ready_sequence):
        job = MagicMock()
        job.ready.side_effect = list(ready_sequence)
        return job

    def test_returns_true_when_group_completes(self):
        job = self._job([False, True])
        with patch('Suricatoos.tasks.time.sleep'):
            ok = join_group_with_timeout(job, label='t', timeout=100)
        self.assertTrue(ok)
        job.revoke.assert_not_called()

    def test_times_out_and_revokes_children(self):
        job = self._job([False, False, False])
        # monotonic: 1st call builds the deadline (1000+10=1010); 2nd call (in-loop)
        # returns 1011 >= deadline -> revoke + bail.
        with patch('Suricatoos.tasks.time.sleep'), \
             patch('Suricatoos.tasks.time.monotonic', side_effect=[1000.0, 1011.0]):
            ok = join_group_with_timeout(job, label='t', timeout=10)
        self.assertFalse(ok)
        job.revoke.assert_called_once_with(terminate=True, signal='SIGKILL')

    def test_timeout_zero_is_unbounded(self):
        # timeout=0 -> no deadline; just wait for ready. monotonic must NOT be needed.
        job = self._job([False, False, True])
        with patch('Suricatoos.tasks.time.sleep'):
            ok = join_group_with_timeout(job, label='t', timeout=0)
        self.assertTrue(ok)
        job.revoke.assert_not_called()


# --------------------------------------------------------------------------- #
# 2. _read_lines_until_dead — interruptible streaming read (the primary fix)  #
# --------------------------------------------------------------------------- #
class _FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)
    def readline(self):
        return self._lines.pop(0) if self._lines else ''


class _FakeProc:
    def __init__(self, lines=(), poll_value=None):
        self.stdout = _FakeStdout(lines)
        self._poll_value = poll_value
    def poll(self):
        return self._poll_value


class ReadLinesUntilDeadTests(unittest.TestCase):
    def test_yields_all_lines_then_eof(self):
        proc = _FakeProc(lines=['a\n', 'b\n'])   # then readline() -> '' (EOF)
        with patch('Suricatoos.tasks.select.select',
                   return_value=([proc.stdout], [], [])):
            out = list(_read_lines_until_dead(proc, {'timed_out': False}))
        self.assertEqual(out, ['a\n', 'b\n'])

    def test_breaks_on_watchdog_even_without_eof(self):
        # The wedge scenario: select NEVER reports data (a grandchild holds the pipe,
        # so readline would block on an EOF that never comes) but the watchdog fired.
        # The reader MUST stop instead of hanging.
        proc = _FakeProc(lines=[])               # readline never called (select not ready)
        with patch('Suricatoos.tasks.select.select', return_value=([], [], [])):
            out = list(_read_lines_until_dead(proc, {'timed_out': True}))
        self.assertEqual(out, [])

    def test_breaks_when_process_exited_and_idle(self):
        proc = _FakeProc(lines=[], poll_value=-9)  # killed; no more data coming
        with patch('Suricatoos.tasks.select.select', return_value=([], [], [])):
            out = list(_read_lines_until_dead(proc, {'timed_out': False}))
        self.assertEqual(out, [])

    def test_waits_then_resumes_when_alive(self):
        # Not-ready while alive must NOT break early; it resumes when data arrives.
        proc = _FakeProc(lines=['x\n'])
        seq = [([], [], []), ([proc.stdout], [], []), ([proc.stdout], [], [])]
        with patch('Suricatoos.tasks.select.select', side_effect=seq):
            out = list(_read_lines_until_dead(proc, {'timed_out': False}, poll=0))
        self.assertEqual(out, ['x\n'])


# --------------------------------------------------------------------------- #
# 3. Queue routing — coordinators isolated off the prefork main_scan_queue    #
# --------------------------------------------------------------------------- #
class QueueRoutingTests(unittest.TestCase):
    def test_coordinators_on_coordinator_queue(self):
        # The blocking orchestrators must NOT share main_scan_queue with their children.
        self.assertEqual(vulnerability_scan.queue, 'coordinator_queue')
        self.assertEqual(nuclei_scan.queue, 'coordinator_queue')

    def test_nmap_off_main_scan_queue(self):
        self.assertEqual(nmap.queue, 'nmap_queue')

    def test_heavy_leaf_children_stay_on_main_scan_queue(self):
        # Memory-bounded prefork pool keeps the heavy leaves; only blocking parents move.
        self.assertEqual(nuclei_individual_severity_module.queue, 'main_scan_queue')
        self.assertEqual(dalfox_xss_scan.queue, 'main_scan_queue')
        self.assertEqual(crlfuzz_scan.queue, 'main_scan_queue')
        self.assertEqual(s3scanner.queue, 'main_scan_queue')


# --------------------------------------------------------------------------- #
# 4. hang_monitor — periodic backstop                                         #
# --------------------------------------------------------------------------- #
class HangMonitorTests(TestCase):
    def setUp(self):
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        self.Domain, self.EngineType, self.ScanHistory = Domain, EngineType, ScanHistory
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')

    def _scan(self, status, start_ago_s, celery_ids=None):
        return self.ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now() - timedelta(seconds=start_ago_s),
            scan_status=status, celery_ids=celery_ids or [])

    def _activity(self, scan, status, age_s):
        from startScan.models import ScanActivity
        return ScanActivity.objects.create(
            scan_of=scan, title='x', name='x', status=status,
            time=timezone.now() - timedelta(seconds=age_s))

    @patch('Suricatoos.tasks.app.control.revoke')
    def test_aborts_stale_running_scan(self, revoke):
        scan = self._scan(RUNNING_TASK, start_ago_s=40000, celery_ids=['abc'])
        self._activity(scan, RUNNING_TASK, age_s=40000)   # last progress long ago
        aborted = hang_monitor()
        scan.refresh_from_db()
        self.assertEqual(aborted, 1)
        self.assertEqual(scan.scan_status, ABORTED_TASK)
        self.assertIsNotNone(scan.stop_scan_date)
        revoke.assert_called_once_with('abc', terminate=True, signal='SIGKILL')

    @patch('Suricatoos.tasks.app.control.revoke')
    def test_leaves_recently_active_running_scan(self, revoke):
        scan = self._scan(RUNNING_TASK, start_ago_s=40000)
        self._activity(scan, RUNNING_TASK, age_s=30)      # progressed 30s ago
        aborted = hang_monitor()
        scan.refresh_from_db()
        self.assertEqual(aborted, 0)
        self.assertEqual(scan.scan_status, RUNNING_TASK)
        revoke.assert_not_called()

    @patch('Suricatoos.tasks.app.control.revoke')
    def test_ignores_finished_scans(self, revoke):
        scan = self._scan(SUCCESS_TASK, start_ago_s=40000)
        self._activity(scan, SUCCESS_TASK, age_s=40000)
        aborted = hang_monitor()
        scan.refresh_from_db()
        self.assertEqual(aborted, 0)
        self.assertEqual(scan.scan_status, SUCCESS_TASK)

    @patch('Suricatoos.tasks.app.control.revoke')
    def test_aborts_running_scan_with_no_activity_yet(self, revoke):
        # Stuck at kickoff: RUNNING, old start, zero activities -> still auto-aborted.
        scan = self._scan(RUNNING_TASK, start_ago_s=40000)
        aborted = hang_monitor()
        scan.refresh_from_db()
        self.assertEqual(aborted, 1)
        self.assertEqual(scan.scan_status, ABORTED_TASK)
