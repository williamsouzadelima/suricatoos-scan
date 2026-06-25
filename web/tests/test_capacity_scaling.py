"""Tests for the machine-capacity-proportional orchestration timers.

Background (user directive): the orchestration timeouts are absolute values
calibrated for the baseline 2-vCPU box. On a larger deployment that takes on
heavier / more concurrent scans, tools and barriers legitimately run longer
(resource contention), so the time budgets must scale UP with capacity to avoid
premature kills.

A single capacity factor ``F`` scales every *duration* timer UNIFORMLY. Uniform
scaling is the safety property: multiplying all timers by the same ``F`` preserves
their ordering by construction:

    watchdog (COMMAND_EXEC) <= CELERY soft <= CELERY hard <= HANG_MONITOR stale
    DIR_FUZZ_TIME_BUDGET    <  CELERY soft

``F = max(1.0, detected_cpus / baseline)`` clamped to ``[1.0, MAX]``. baseline=2
=> F == 1.0 on this 2-CPU box => ZERO live behavior change. The factor only ever
ENLARGES, never shrinks.

Run with:  python3 manage.py test tests.test_capacity_scaling
"""
import os
import unittest

from Suricatoos.capacity import compute_capacity_factor, scale_timer


class ComputeCapacityFactorTests(unittest.TestCase):
    """Pure-function tests for the factor computation (no Django needed)."""

    def test_baseline_is_no_op(self):
        # 2 cpus / baseline 2 => 1.0 (the live box; no scaling).
        self.assertEqual(compute_capacity_factor(2, 2, 8), 1.0)

    def test_linear_scaling(self):
        # 8 cpus / baseline 2 => 4.0 (linear below the ceiling).
        self.assertEqual(compute_capacity_factor(8, 2, 8), 4.0)

    def test_never_shrinks_below_one(self):
        # 1 cpu / baseline 2 = 0.5, but clamped UP to 1.0 (only enlarges).
        self.assertEqual(compute_capacity_factor(1, 2, 8), 1.0)

    def test_clamped_to_max(self):
        # 64 cpus / baseline 2 = 32, clamped DOWN to the ceiling 8.0.
        self.assertEqual(compute_capacity_factor(64, 2, 8), 8.0)

    def test_explicit_override_wins(self):
        self.assertEqual(compute_capacity_factor(2, 2, 8, explicit='3.5'), 3.5)

    def test_explicit_override_clamped_to_max(self):
        self.assertEqual(compute_capacity_factor(2, 2, 8, explicit='100'), 8.0)

    def test_explicit_override_clamped_up_to_one(self):
        self.assertEqual(compute_capacity_factor(2, 2, 8, explicit='0.1'), 1.0)

    def test_explicit_override_garbage_falls_back_to_one(self):
        self.assertEqual(compute_capacity_factor(2, 2, 8, explicit='garbage'), 1.0)

    def test_explicit_empty_string_is_ignored(self):
        # Empty/whitespace explicit means "not set" -> fall through to cpus/baseline.
        self.assertEqual(compute_capacity_factor(8, 2, 8, explicit=''), 4.0)
        self.assertEqual(compute_capacity_factor(8, 2, 8, explicit='   '), 4.0)


class ScaleTimerTests(unittest.TestCase):
    """Pure-function tests for the timer scaler."""

    def test_zero_disable_sentinel_preserved(self):
        # 0 means "disabled" everywhere it is used; scaling must keep it 0.
        self.assertEqual(scale_timer(0, 4.0), 0)

    def test_scaling_doubles(self):
        self.assertEqual(scale_timer(4200, 2.0), 8400)

    def test_factor_one_is_identity(self):
        self.assertEqual(scale_timer(900, 1.0), 900)

    def test_rounds_to_int(self):
        # 600 * 1.5 = 900 exactly; 601 * 1.5 = 901.5 -> 902 (round-half-to-even/up).
        self.assertEqual(scale_timer(600, 1.5), 900)
        self.assertIsInstance(scale_timer(601, 1.5), int)

    def test_none_factor_uses_module_default(self):
        # On this 2-CPU box CAPACITY_FACTOR == 1.0, so default scaling is identity.
        from Suricatoos import capacity
        self.assertEqual(scale_timer(1234), int(round(1234 * capacity.CAPACITY_FACTOR)))


# Base (un-scaled) constants the orchestration ordering is built on.
BASE_WATCHDOG = 7200    # DEFAULT_COMMAND_EXEC_TIMEOUT
BASE_SOFT = 5400        # CELERY_TASK_SOFT_TIME_LIMIT
BASE_HARD = 7200        # CELERY_TASK_TIME_LIMIT
BASE_STALE = 9000       # HANG_MONITOR_STALE_AFTER
BASE_BUDGET = 4200      # DIR_FUZZ_TIME_BUDGET


class OrderingInvariantTests(unittest.TestCase):
    """Uniform scaling must preserve the ordering at every factor F >= 1."""

    def _assert_ordering(self, f):
        watchdog = scale_timer(BASE_WATCHDOG, f)
        soft = scale_timer(BASE_SOFT, f)
        hard = scale_timer(BASE_HARD, f)
        stale = scale_timer(BASE_STALE, f)
        budget = scale_timer(BASE_BUDGET, f)
        # dir-fuzz must finish strictly before the soft kill.
        self.assertLess(budget, soft, f'budget<soft failed at F={f}')
        # soft kill before hard kill.
        self.assertLess(soft, hard, f'soft<hard failed at F={f}')
        # hard kill before the hang monitor aborts the whole scan.
        self.assertLessEqual(hard, stale, f'hard<=stale failed at F={f}')
        # the per-tool watchdog must not exceed the hard limit.
        self.assertLessEqual(watchdog, hard, f'watchdog<=hard failed at F={f}')

    def test_ordering_holds_at_f1(self):
        self._assert_ordering(1.0)

    def test_ordering_holds_at_f2(self):
        self._assert_ordering(2.0)

    def test_ordering_holds_at_f4(self):
        self._assert_ordering(4.0)

    def test_ordering_holds_at_f8(self):
        self._assert_ordering(8.0)


class LiveConstantsRegressionTests(unittest.TestCase):
    """Regression guard: on this 2-CPU box (no env overrides) the resolved factor
    is exactly 1.0 and every live constant equals its ORIGINAL base value, i.e. the
    feature is a verified no-op on the baseline box."""

    def test_capacity_factor_is_one_on_this_box(self):
        from Suricatoos import capacity
        # No env override set in the test environment.
        self.assertIsNone(os.environ.get('SURICATOOS_CAPACITY_FACTOR') or None)
        self.assertEqual(capacity.CAPACITY_FACTOR, 1.0)

    def test_definitions_constants_unchanged(self):
        from Suricatoos import definitions as d
        self.assertEqual(d.DIR_FUZZ_TIME_BUDGET, BASE_BUDGET)
        self.assertEqual(d.DIR_FUZZ_MIN_PER_HOST, 30)
        self.assertEqual(d.THEHARVESTER_EXEC_TIMEOUT, 600)
        self.assertEqual(d.SPIDERFOOT_EXEC_TIMEOUT, 900)
        self.assertEqual(d.DEFAULT_COMMAND_EXEC_TIMEOUT, BASE_WATCHDOG)
        # ORCHESTRATION_BARRIER_TIMEOUT is set verbatim by docker-compose (7200);
        # default also 7200, so either way it resolves to 7200 here.
        self.assertEqual(d.DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT, 7200)
        self.assertEqual(d.HANG_MONITOR_STALE_AFTER, BASE_STALE)

    def test_celery_limits_unchanged(self):
        from django.conf import settings
        self.assertEqual(settings.CELERY_TASK_SOFT_TIME_LIMIT, BASE_SOFT)
        self.assertEqual(settings.CELERY_TASK_TIME_LIMIT, BASE_HARD)

    def test_live_ordering_holds(self):
        # The resolved live constants themselves must satisfy the ordering.
        from Suricatoos import definitions as d
        from django.conf import settings
        self.assertLess(d.DIR_FUZZ_TIME_BUDGET, settings.CELERY_TASK_SOFT_TIME_LIMIT)
        self.assertLess(settings.CELERY_TASK_SOFT_TIME_LIMIT, settings.CELERY_TASK_TIME_LIMIT)
        self.assertLessEqual(settings.CELERY_TASK_TIME_LIMIT, d.HANG_MONITOR_STALE_AFTER)
        self.assertLessEqual(d.DEFAULT_COMMAND_EXEC_TIMEOUT, settings.CELERY_TASK_TIME_LIMIT)


class DepthTierFactorTests(unittest.TestCase):
    """Scan depth tiers: per-tier timer scaling composes with the capacity factor."""

    def test_tier_factor_values(self):
        from Suricatoos.capacity import tier_factor
        self.assertEqual(tier_factor('fast'), 0.4)
        self.assertEqual(tier_factor('medium'), 1.0)
        self.assertEqual(tier_factor('deep'), 4.0)

    def test_tier_factor_unknown_defaults_to_medium(self):
        from Suricatoos.capacity import tier_factor
        self.assertEqual(tier_factor('bogus'), 1.0)
        self.assertEqual(tier_factor(None), 1.0)

    def test_normalize_tier(self):
        from Suricatoos.capacity import normalize_tier
        self.assertEqual(normalize_tier('Deep'), 'deep')
        self.assertEqual(normalize_tier('  fast '), 'fast')
        self.assertEqual(normalize_tier(None), 'medium')
        self.assertEqual(normalize_tier('nope'), 'medium')

    def test_scale_for_tier_preserves_zero_sentinel(self):
        from Suricatoos.capacity import scale_for_tier
        self.assertEqual(scale_for_tier(0, 'deep'), 0)

    def test_scale_for_tier_composes_with_capacity(self):
        from Suricatoos.capacity import scale_for_tier, scale_timer
        self.assertEqual(scale_for_tier(100, 'fast'), scale_timer(40))
        self.assertEqual(scale_for_tier(100, 'medium'), scale_timer(100))
        self.assertEqual(scale_for_tier(100, 'deep'), scale_timer(400))

    def test_port_scan_ceiling_deep_multi_day_finite(self):
        from Suricatoos.capacity import port_scan_ceiling, scale_timer
        c = port_scan_ceiling('deep')
        self.assertEqual(c, scale_timer(14 * 24 * 3600))
        self.assertGreater(c, 0)

    def test_port_scan_ceiling_ordered_by_tier(self):
        from Suricatoos.capacity import port_scan_ceiling
        self.assertLess(port_scan_ceiling('fast'), port_scan_ceiling('medium'))
        self.assertLess(port_scan_ceiling('medium'), port_scan_ceiling('deep'))

    def test_scan_time_limit_deep_exceeds_port_ceiling(self):
        from Suricatoos.capacity import scan_time_limit, port_scan_ceiling
        self.assertGreater(scan_time_limit('deep'), port_scan_ceiling('deep'))


if __name__ == '__main__':
    unittest.main()
