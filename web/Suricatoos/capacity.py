"""Machine-capacity-proportional scaling for orchestration *duration* timers.

User directive: *"se a capacidade da maquina for maior, temos que ampliar os
temporizadores proporcionalmente."* The scan orchestration timeouts are absolute
values calibrated for the baseline 2-vCPU box. On a larger deployment that takes on
heavier / more concurrent scans, tools and barriers legitimately run longer
(resource contention), so the budgets must scale UP with capacity to avoid
premature kills.

Design (single capacity factor ``F``):

    F = clamp(detected_cpus / baseline_cpus, 1.0, MAX)

Every duration timer is multiplied by the SAME ``F`` (``scale_timer``). Uniform
scaling is the safety property -- it preserves the ordering by construction:

    watchdog (COMMAND_EXEC) <= CELERY soft <= CELERY hard <= HANG_MONITOR stale
    DIR_FUZZ_TIME_BUDGET    <  CELERY soft

so a stuck subprocess is still caught by its watchdog before Celery soft-kills the
task, the task is still hard-killed before the hang monitor aborts the whole scan,
and dir-fuzz still finishes under the soft limit -- at ANY ``F``.

``F`` only ever ENLARGES (clamped >= 1.0), so a smaller box never has its timers
shrunk. baseline = 2 => F == 1.0 on this box => the feature is a verified no-op
here (byte-identical live constants).

This module imports ONLY ``os`` -- no Django, no project imports -- so both
``definitions.py`` and ``settings.py`` can import it with zero circular-import risk.

Knobs (all optional, read at import):
    TIMER_BASELINE_CPUS            env, default 2     -- the calibration box size.
    SURICATOOS_CAPACITY_FACTOR_MAX env, default 8.0   -- the ceiling on F.
    SURICATOOS_CAPACITY_FACTOR     env, explicit float override (wins over CPU detection).
"""
import os

DEFAULT_BASELINE_CPUS = 2
DEFAULT_FACTOR_MAX = 8.0


def _detect_cpus():
    """Number of CPUs usable by THIS process.

    ``os.sched_getaffinity`` is cgroup/cpuset-aware on Linux (respects container
    CPU pinning); fall back to ``os.cpu_count`` where it is unavailable.
    """
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def compute_capacity_factor(detected_cpus, baseline_cpus, factor_max, explicit=None):
    """Pure. Compute the capacity factor.

    ``explicit`` (float|str|None) wins if present and parseable; otherwise the
    factor is ``detected_cpus / baseline_cpus``. The result is ALWAYS clamped to
    ``[1.0, factor_max]`` -- it only ever enlarges, never shrinks, and never
    exceeds the ceiling.
    """
    if explicit is not None and str(explicit).strip() != '':
        try:
            val = float(explicit)
        except (TypeError, ValueError):
            val = 1.0
    else:
        try:
            val = float(detected_cpus) / float(max(1, baseline_cpus))
        except (TypeError, ValueError, ZeroDivisionError):
            val = 1.0
    return min(float(factor_max), max(1.0, val))


def _resolve_int_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _resolve_float_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


# Resolved once at import time.
TIMER_BASELINE_CPUS = _resolve_int_env('TIMER_BASELINE_CPUS', DEFAULT_BASELINE_CPUS)
SURICATOOS_CAPACITY_FACTOR_MAX = _resolve_float_env(
    'SURICATOOS_CAPACITY_FACTOR_MAX', DEFAULT_FACTOR_MAX)
# Explicit override is kept as the raw string (None if unset/empty) so the pure
# function applies its own parse/clamp/fallback semantics.
_EXPLICIT_FACTOR = os.environ.get('SURICATOOS_CAPACITY_FACTOR')

CAPACITY_FACTOR = compute_capacity_factor(
    _detect_cpus(),
    TIMER_BASELINE_CPUS,
    SURICATOOS_CAPACITY_FACTOR_MAX,
    explicit=_EXPLICIT_FACTOR,
)


def scale_timer(seconds, factor=None):
    """Scale a duration (seconds) by the capacity factor.

    ``0`` is the "disabled" sentinel used across the codebase (e.g.
    ``DEFAULT_COMMAND_EXEC_TIMEOUT`` / ``DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT``)
    and is preserved unchanged. ``factor`` defaults to the module
    ``CAPACITY_FACTOR``.
    """
    f = CAPACITY_FACTOR if factor is None else factor
    if not seconds:
        return seconds
    return int(round(seconds * f))


# --- Scan depth tiers (Fast / Medium / Deep) -------------------------------------------
# Each depth-tier engine carries depth_tier=fast|medium|deep in its yaml_configuration.
# Duration timers scale by capacity factor AND tier factor (both finite), preserving the
# watchdog ordering at every tier. medium == 1.0 == today's behaviour (no-op for the
# existing engines, which have no depth_tier -> normalize to medium).
_TIER_FACTORS = {'fast': 0.4, 'medium': 1.0, 'deep': 4.0}
_DEEP_PORT_SCAN_SECONDS = 14 * 24 * 3600   # ~14 days finite ceiling for nmap -sU -p-
_DEEP_SCAN_LIMIT_SECONDS = 21 * 24 * 3600  # ~21 days finite ceiling for the whole deep scan


def normalize_tier(value):
    """Coerce a raw depth_tier value to one of fast|medium|deep (default medium)."""
    t = str(value).strip().lower() if value is not None else ''
    return t if t in _TIER_FACTORS else 'medium'


def tier_factor(tier):
    """Per-tier duration multiplier. Unknown/None -> 1.0 (medium)."""
    return _TIER_FACTORS.get(normalize_tier(tier), 1.0)


def scale_for_tier(seconds, tier):
    """scale_timer(seconds) further multiplied by the tier factor. Keeps the 0 sentinel."""
    if not seconds:
        return seconds
    return int(round(scale_timer(seconds) * tier_factor(tier)))


def port_scan_ceiling(tier):
    """Per-command timeout for the port_scan stage. Deep gets a dedicated multi-day (but
    finite) ceiling because nmap -sU -p- legitimately runs for days/weeks."""
    if normalize_tier(tier) == 'deep':
        return scale_timer(_DEEP_PORT_SCAN_SECONDS)
    return scale_for_tier(7200, tier)


def scan_time_limit(tier):
    """Whole-scan Celery time limit. Deep covers the long port_scan plus the other stages."""
    if normalize_tier(tier) == 'deep':
        return scale_timer(_DEEP_SCAN_LIMIT_SECONDS)
    return scale_for_tier(7200, tier)
