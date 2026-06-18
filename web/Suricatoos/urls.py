from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from Suricatoos.views import serve_protected_media, serve_branding_asset, serve_spa
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

schema_view = get_schema_view(
   openapi.Info(
      title="Suricatoos API",
      default_version='v1',
      description="Suricatoos: An Automated reconnaissance framework.",
      contact=openapi.Contact(email="williamsouzadelima@gmail.com"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    url(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    url(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    # i18n set_language endpoint (POST) for the topbar language switcher
    path('i18n/', include('django.conf.urls.i18n')),
    path(
        'admin/',
        admin.site.urls),
    # API first: reserve the /api/ namespace so it never collides with the
    # dashboard's <slug:slug>/... routes (e.g. /api/projects/ vs <slug>/projects/).
    path('api/', include('api.urls', 'api')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path(
        '',
        include('dashboard.urls')),
    path(
        'target/',
        include('targetApp.urls')),
    path(
        'scanEngine/',
        include('scanEngine.urls')),
    path(
        'scan/',
        include('startScan.urls')),
    path(
        'recon_note/',
        include('recon_note.urls')),
    path(
        'login/',
        auth_views.LoginView.as_view(template_name='base/login.html'),
        name='login'),
    path(
        'logout/',
        auth_views.LogoutView.as_view(template_name='base/logout.html'),
        name='logout'),
    # SPA mounted at /app/* (client-side routing -> serve the shell for any subpath)
    re_path(r'^app(?:/.*)?$', serve_spa, name='spa'),
    path(
        'media/<path:path>',
        serve_protected_media,
        name='serve_protected_media'
    ),
    path(
        'branding-asset/<path:path>',
        serve_branding_asset,
        name='branding_asset'
    ),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
# ] + static(settings.MEDIA_URL, document_root=settings.SURICATOOS_RESULTS) + \
    
