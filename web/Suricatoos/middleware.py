from django.conf import settings

from dashboard.models import UserPreferences

class UserPreferencesMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		if request.user.is_authenticated:
			request.user_preferences, created = UserPreferences.objects.get_or_create(user=request.user)
		return self.get_response(request)


class ContentSecurityPolicyMiddleware:
	"""OWASP A05-1 — emit a baseline Content-Security-Policy.

	The app renders attacker-influenced reconnaissance output (subdomain/title/
	tech/banner strings) into client-rendered DataTables. CSP is the second layer
	behind output escaping: if any escaping miss slips through, these directives
	still blunt the impact. The default policy is deliberately the *safe subset*
	that does NOT require touching the inline <script> blocks in base.html/login.html
	(no restrictive default-src/script-src), so it is non-breaking:

	  object-src 'none'    -> no plugin/embed-based script execution
	  base-uri 'self'      -> no <base> tag hijack of relative URLs
	  frame-ancestors 'none' -> clickjacking protection (beyond X-Frame-Options)

	Operators can tighten/replace it via the SURICATOOS_CSP env var.
	"""

	def __init__(self, get_response):
		self.get_response = get_response
		self.policy = getattr(settings, 'CONTENT_SECURITY_POLICY', '').strip()

	def __call__(self, request):
		response = self.get_response(request)
		if self.policy and 'Content-Security-Policy' not in response:
			response['Content-Security-Policy'] = self.policy
		return response
