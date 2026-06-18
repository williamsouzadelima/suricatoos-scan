import os
import mimetypes
from django.contrib.auth.decorators import login_required
from django.contrib.staticfiles import finders
from django.http import HttpResponse, Http404, FileResponse
from django.conf import settings
from django.utils.translation import gettext_lazy as _t


def serve_spa(request, path=''):
    """Serve the built SPA shell for /app/* (React client-side routing -> all
    sub-paths return index.html). Public: the SPA does its own JWT auth in the
    browser. Assets are served by nginx from /staticfiles/spa/."""
    index = finders.find('spa/index.html') or os.path.join(
        settings.STATIC_ROOT, 'spa', 'index.html')
    if not os.path.isfile(index):
        raise Http404(_t("SPA build not found. Run the frontend build."))
    with open(index, 'r', encoding='utf-8') as f:
        response = HttpResponse(f.read())
    # Defence-in-depth CSP for the SPA shell: the built bundle loads only
    # same-origin hashed JS/CSS (no inline scripts), so 'self' for script-src
    # is safe and blocks injected/3rd-party script if a future XSS sink appears.
    # 'unsafe-inline' stays on style-src for React inline style attributes.
    response['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def serve_branding_asset(request, path):
    """Serve a white-label branding asset (logo/favicon) PUBLICLY.

    Branding files are uploaded under MEDIA_ROOT/branding/ but, unlike scan
    results, are not sensitive and must render on the unauthenticated login page
    (and as the favicon). Only a basename within branding/ is served, so this
    can't be used to read arbitrary files.
    """
    # Resolve the file from the branding model, not from the request path: only
    # the (up to) three files the model actually references are servable, and the
    # filesystem path comes from the FileField storage (trusted DB value). The
    # request value is used solely for an equality match against the stored
    # basenames, so no request-controlled data ever reaches open()/isfile() —
    # this closes the path-traversal class outright (and the CodeQL alert).
    from scanEngine.models import BrandingSetting
    requested = os.path.basename(path)
    branding = BrandingSetting.load()
    for field in (branding.logo_dark, branding.logo_light, branding.favicon):
        if not field:
            continue
        if os.path.basename(field.name) == requested:
            file_path = field.path
            if os.path.isfile(file_path):
                content_type, _ = mimetypes.guess_type(file_path)
                return FileResponse(
                    open(file_path, 'rb'),
                    content_type=content_type or 'application/octet-stream')
            break
    raise Http404(_t("File not found"))


@login_required
def serve_protected_media(request, path):
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.isdir(file_path):
        raise Http404(_t("File not found"))
    if os.path.exists(file_path):
        content_type, _ = mimetypes.guess_type(file_path)
        response = HttpResponse()
        # response['Content-Disposition'] = f'attachment; filename={os.path.basename(file_path)}'
        response['Content-Type'] = content_type
        response['X-Accel-Redirect'] = f'/protected_media/{path}'
        return response
    else:
        raise Http404(_t("File not found"))

