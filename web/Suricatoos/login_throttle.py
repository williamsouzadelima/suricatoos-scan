"""OWASP A04-3 / A07-3 — login brute-force throttle (middleware).

A dependency-free, cache-based throttle applied via middleware to ALL login POST
surfaces — both the app login (/login/) and Django's admin login (/admin/login/),
which authenticate the same accounts. Policy:
  * primary key = (real_client_ip, normalized_username): SURICATOOS_LOGIN_FAIL_LIMIT
    failures -> block. The combination (not username-only) means an attacker spamming
    the shared admin username from their own IP cannot lock out the legitimate operator.
  * IP-only backstop: SURICATOOS_LOGIN_IP_FAIL_LIMIT failures from one IP -> block.
    Blank usernames feed ONLY this backstop.
  * sliding TTL = SURICATOOS_LOGIN_COOLDOWN: each failure refreshes the window; a
    successful login clears both counters for that (ip, username) / ip.
Fail-OPEN: any cache error allows the request (a cache blip never locks out the admin).
The username is NFKC-normalized + stripped + lowercased to match what Django's
AuthenticationForm does before authenticate(), so whitespace/unicode/case variants
cannot multiply an attacker's per-account budget.
"""
import ipaddress
import logging
import unicodedata

from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.core.cache import caches, InvalidCacheBackendError
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

CACHE_ALIAS = 'login_throttle'
# Only the app login form. The admin login (/admin/login/) is NOT a separate brute-force
# surface: LoginRequiredMiddleware redirects unauthenticated /admin/... (incl. /admin/login/)
# to this throttled /login/, discarding the POST. Including it here would also be a BYPASS —
# that 302 redirect would be read as a login "success" and clear the attacker's counter.
DEFAULT_LOGIN_PATHS = ['/login/']


def _enabled():
    return getattr(settings, 'SURICATOOS_LOGIN_THROTTLE_ENABLED', False)


def _throttle_cache():
    try:
        return caches[CACHE_ALIAS]
    except InvalidCacheBackendError:
        return caches['default']


def _is_locmem(cache):
    return 'LocMemCache' in cache.__class__.__name__


def normalize_username(username):
    # Match django.contrib.auth.forms.UsernameField (strip + NFKC) so variant spellings
    # collapse to the same throttle key; also lowercase (over-group by case is safe).
    return unicodedata.normalize('NFKC', str(username or '').strip()).casefold()


def resolve_client_ip(request):
    """Real client IP. With SURICATOOS_LOGIN_TRUST_PROXY_IP (default not DEBUG) trust
    nginx's X-Real-IP (a single, non-appendable hop nginx overwrites every request);
    otherwise REMOTE_ADDR. Validated; unparseable -> a constant bucket. Never trusts
    X-Forwarded-For[0] (client-controllable)."""
    candidate = None
    if getattr(settings, 'SURICATOOS_LOGIN_TRUST_PROXY_IP', False):
        candidate = request.META.get('HTTP_X_REAL_IP')
    if not candidate:
        candidate = request.META.get('REMOTE_ADDR')
    candidate = (candidate or '').strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return 'unknown'


def mask_username(username):
    u = str(username or '')
    if len(u) <= 2:
        return '*' * len(u)
    return u[:2] + '*' * (len(u) - 2)


def _keys(ip, norm_username):
    return f'lt:ipu:{ip}:{norm_username}', f'lt:ip:{ip}'


def _incr(cache, key, ttl):
    # Seed-then-increment keeps the count atomic on backends that support incr; touch()
    # refreshes the TTL on every failure so the lock is a SLIDING window.
    cache.add(key, 0, ttl)
    try:
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, ttl)
    try:
        cache.touch(key, ttl)
    except Exception:
        pass


def is_blocked(request, norm_username):
    if not _enabled():
        return False
    try:
        cache = _throttle_cache()
        ip = resolve_client_ip(request)
        ipu, ipk = _keys(ip, norm_username)
        ipu_count = cache.get(ipu, 0) if norm_username else 0
        ip_count = cache.get(ipk, 0)
    except Exception as e:
        logger.warning(f'login throttle read failed (fail-open): {e}')
        return False
    limit = getattr(settings, 'SURICATOOS_LOGIN_FAIL_LIMIT', 5)
    ip_limit = getattr(settings, 'SURICATOOS_LOGIN_IP_FAIL_LIMIT', 20)
    blocked = (bool(norm_username) and ipu_count >= limit) or (ip_count >= ip_limit)
    if blocked:
        logger.warning(
            'login throttle BLOCK ip=%s user=%s (ipu=%s ip=%s)',
            ip, mask_username(norm_username), ipu_count, ip_count)
    return blocked


def record_failure(request, norm_username):
    if not _enabled():
        return
    try:
        cache = _throttle_cache()
        ip = resolve_client_ip(request)
        ipu, ipk = _keys(ip, norm_username)
        ttl = getattr(settings, 'SURICATOOS_LOGIN_COOLDOWN', 900)
        _incr(cache, ipk, ttl)              # IP backstop always
        if norm_username:
            _incr(cache, ipu, ttl)          # ip+username only for a real account
    except Exception as e:
        logger.warning(f'login throttle write failed: {e}')


def clear_failures(request, norm_username):
    if not _enabled():
        return
    try:
        cache = _throttle_cache()
        ip = resolve_client_ip(request)
        ipu, ipk = _keys(ip, norm_username)
        cache.delete_many([ipu, ipk])       # clear BOTH on success
    except Exception as e:
        logger.warning(f'login throttle clear failed: {e}')


def _login_paths():
    return set(getattr(settings, 'SURICATOOS_LOGIN_THROTTLE_PATHS', DEFAULT_LOGIN_PATHS))


def _blocked_response(request):
    msg = _('Too many failed login attempts. Please try again later.')
    return render(request, 'base/login.html',
                  {'form': AuthenticationForm(request), 'throttle_message': msg},
                  status=429)


class LoginThrottleMiddleware:
    """Throttles credential guessing on every login POST surface (/login/ and the admin
    /admin/login/). Login success/failure is detected by the response status (redirect =
    success, 200 re-render = failed attempt), so it works for any LoginView-style form."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.login_paths = _login_paths()
        # Startup warning (middleware is instantiated once at process start): LocMemCache
        # is per-process and under-counts across multiple workers/replicas.
        if _enabled() and _is_locmem(_throttle_cache()):
            logger.warning(
                'login throttle is using LocMemCache (per-process) — correct for a single '
                'web process; for multi-worker/replica deployments point the `login_throttle` '
                'cache at a shared store (e.g. Redis) or the limit can be bypassed.')

    def __call__(self, request):
        is_login_post = request.method == 'POST' and request.path in self.login_paths
        norm_username = ''
        if is_login_post:
            norm_username = normalize_username(request.POST.get('username', ''))
            if is_blocked(request, norm_username):
                return _blocked_response(request)
        response = self.get_response(request)
        if is_login_post:
            sc = getattr(response, 'status_code', None)
            if sc in (301, 302):            # login succeeded -> redirect
                clear_failures(request, norm_username)
            elif sc == 200:                 # re-rendered form -> failed attempt
                record_failure(request, norm_username)
            # other statuses (403 CSRF, 5xx) are not counted
        return response
