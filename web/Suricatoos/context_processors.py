from dashboard.models import *
from django.conf import settings


def projects(request):
    projects = Project.objects.all()
    try:
        slug = request.resolver_match.kwargs.get('slug')
        project = Project.objects.get(slug=slug)
    except Exception:
        project = None
    return {
        'projects': projects,
        'current_project': project
    }

def version_context(request):
    return {
        'SURICATOOS_CURRENT_VERSION': settings.SURICATOOS_CURRENT_VERSION
    }

def user_preferences(request):
    if hasattr(request, 'user_preferences'):
        return {'user_preferences': request.user_preferences}
    return {}

def branding(request):
    """Inject the install-wide white-label branding into every template.

    Templates use {{ branding.logo_dark_url }} / logo_light_url / favicon_url /
    name. Falls back to the bundled Suricatoos defaults if the table is missing
    (e.g. mid-migration) so rendering never breaks.
    """
    from scanEngine.models import BrandingSetting
    try:
        return {'branding': BrandingSetting.load()}
    except Exception:
        return {'branding': {
            'name': 'Suricatoos',
            'logo_dark_url': BrandingSetting.DEFAULT_LOGO_DARK,
            'logo_light_url': BrandingSetting.DEFAULT_LOGO_LIGHT,
            'favicon_url': BrandingSetting.DEFAULT_FAVICON,
        }}