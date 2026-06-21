"""Break-glass recovery for the login brute-force throttle (OWASP A04-3/A07-3).

Usage:
  python3 manage.py clear_login_lockouts                # clear ALL throttle state
  python3 manage.py clear_login_lockouts --all
  python3 manage.py clear_login_lockouts --ip 1.2.3.4   # clear that IP's backstop
  python3 manage.py clear_login_lockouts --ip 1.2.3.4 --username admin  # clear that pair

Note: the 15-min sliding TTL auto-heals locks on its own; this is for immediate recovery.
Locks only guard the HTTP login form, so `createsuperuser`/shell always bypass the throttle.
"""
from django.core.management.base import BaseCommand

from Suricatoos.login_throttle import CACHE_ALIAS, _keys
from django.core.cache import caches, InvalidCacheBackendError


class Command(BaseCommand):
    help = 'Clear login brute-force throttle counters (recovery).'

    def add_arguments(self, parser):
        parser.add_argument('--all', action='store_true', help='Clear the entire login-throttle cache.')
        parser.add_argument('--ip', help='Client IP whose counters to clear.')
        parser.add_argument('--username', help='Username (used with --ip to clear that pair).')

    def handle(self, *args, **options):
        try:
            cache = caches[CACHE_ALIAS]
        except InvalidCacheBackendError:
            cache = caches['default']

        # LocMemCache is per-process: this command runs in a SEPARATE process from the
        # live web server, so it cannot reach the server's in-memory counters. Warn loudly
        # so the operator uses a working recovery path with the default cache.
        if 'LocMemCache' in cache.__class__.__name__:
            self.stderr.write(self.style.WARNING(
                'login_throttle uses LocMemCache (per-process): this command does NOT clear '
                'the live web process counters. Use one of: wait out the cooldown TTL; set '
                'SURICATOOS_LOGIN_THROTTLE_ENABLED=0 and reload; or restart the web container. '
                'This command only works when login_throttle points at a SHARED cache (e.g. Redis).'))

        ip = options.get('ip')
        username = options.get('username')

        if options.get('all') or (not ip and not username):
            cache.clear()
            self.stdout.write(self.style.SUCCESS('Cleared ALL login-throttle counters.'))
            return

        if not ip:
            self.stderr.write('Provide --ip (optionally with --username), or --all.')
            return

        ipu, ipk = _keys(ip, username or '')
        keys = [ipk] + ([ipu] if username else [])
        cache.delete_many(keys)
        self.stdout.write(self.style.SUCCESS(
            f'Cleared throttle counters for ip={ip}' + (f' username={username}' if username else '')))
