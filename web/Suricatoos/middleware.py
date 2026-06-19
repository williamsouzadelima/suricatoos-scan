from django.conf import settings
from django.shortcuts import redirect

from dashboard.models import UserPreferences

class UserPreferencesMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		if request.user.is_authenticated:
			request.user_preferences, created = UserPreferences.objects.get_or_create(user=request.user)
		return self.get_response(request)


class UICutoverMiddleware:
	"""Hard cutover to the React SPA mounted at /app/.

	When settings.UI_CUTOVER is on, every legacy server-rendered page is
	redirected to the SPA, so the team is forced onto the new interface. Only a
	small allowlist stays reachable: the JSON API (the SPA depends on it), the
	SPA shell + its static assets, protected media/branding, auth, the i18n
	endpoint, swagger and the Django admin — the admin/auth pair is the
	deliberate escape hatch so a missing-SPA-build can never lock everyone out.

	This is intentionally a single, env-flag-gated gate (SURICATOOS_UI_CUTOVER)
	so the whole cutover can be rolled back in one place: flip the flag off and
	restart, and the legacy interface returns untouched.
	"""

	# Path prefixes that must keep working regardless of the cutover.
	ALLOW_PREFIXES = (
		'/app',            # the SPA shell + client-side routes
		'/api',            # REST API the SPA consumes
		'/staticfiles',    # built assets (SPA bundle lives under /staticfiles/spa/)
		'/static',         # legacy/static fallback
		'/media',          # protected scan media (screenshots, etc.)
		'/branding-asset', # tenant branding assets
		'/admin',          # Django admin — emergency escape hatch
		'/login',          # auth
		'/logout',
		'/i18n',           # set_language endpoint
		'/swagger',        # API docs
		'/__debug__',      # django-debug-toolbar (dev)
	)

	def __init__(self, get_response):
		self.get_response = get_response
		self.enabled = getattr(settings, 'UI_CUTOVER', False)

	def __call__(self, request):
		if self.enabled and not request.path.startswith(self.ALLOW_PREFIXES):
			# Preserve nothing from the legacy URL: the SPA owns its own routing.
			return redirect('/app/')
		return self.get_response(request)
