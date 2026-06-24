import environ

env = environ.FileAwareEnv()

import mimetypes
import os

from Suricatoos.init import first_run
from Suricatoos.utilities import SuricatoosTaskFormatter

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       SURICATOOS CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, os.pardir, '.env'))

# Root env vars
SURICATOOS_HOME = env('SURICATOOS_HOME', default='/usr/src/app')
SURICATOOS_RESULTS = env('SURICATOOS_RESULTS', default=f'{SURICATOOS_HOME}/scan_results')
SURICATOOS_CACHE_ENABLED = env.bool('SURICATOOS_CACHE_ENABLED', default=False)
SURICATOOS_RECORD_ENABLED = env.bool('SURICATOOS_RECORD_ENABLED', default=True)
SURICATOOS_RAISE_ON_ERROR = env.bool('SURICATOOS_RAISE_ON_ERROR', default=False)

# Common env vars
DEBUG = env.bool('DEBUG', default=False)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(SURICATOOS_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=True)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=150) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=30)
DEFAULT_GET_GPT_REPORT = env.bool('DEFAULT_GET_GPT_REPORT', default=True)

# subfinder's provider-config.yaml — where its passive-source API keys (e.g. the
# Shodan key set from the API Vault page) live; auto-loaded by subfinder at scan
# time. Overridable so tests can point it at a temp file.
SUBFINDER_PROVIDER_CONFIG_PATH = os.environ.get(
    'SUBFINDER_PROVIDER_CONFIG_PATH', '/root/.config/subfinder/provider-config.yaml')

# theHarvester's api-keys.yaml (OSINT keys: Hunter, RocketReach, …). Lives in the
# shared github_repos volume so the web container can write what celery reads at
# scan time. Overridable so tests can point it at a temp file.
THEHARVESTER_API_KEYS_PATH = os.environ.get(
    'THEHARVESTER_API_KEYS_PATH', '/usr/src/github/theHarvester/api-keys.yaml')

# Globals
# OWASP A05-2: env-driven so a deployment can restrict the accepted Host headers
# (e.g. ALLOWED_HOSTS=recon.example.com,127.0.0.1). Defaults to the wildcard to
# preserve the inherited behaviour for IP-accessed dev boxes; production should set it.
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['*'])
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# --- Security hardening (OWASP A05/A02/A07) -------------------------------
# Env-flagged so dev/HTTP and the CI test runner keep working. Real users reach
# the app through the nginx HTTPS proxy (443); Secure cookies apply there.
_SECURE_COOKIES = env.bool('SURICATOOS_SECURE_COOKIES', default=not DEBUG)
SESSION_COOKIE_SECURE = _SECURE_COOKIES
CSRF_COOKIE_SECURE = _SECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
# W008 (SECURE_SSL_REDIRECT) is intentionally accepted: nginx owns the http->https
# redirect; enabling it in Django would break internal :8000 health checks. Silenced
# so `check --deploy --fail-level WARNING` can gate genuinely-new misconfiguration.
SILENCED_SYSTEM_CHECKS = ['security.W008']
# HSTS + proxy-SSL-header are OPT-IN (default OFF). Reason: setting
# SECURE_PROXY_SSL_HEADER makes Django treat the proxied request as HTTPS, which
# turns on CSRF strict-referer checking. In this nginx setup that rejects the
# login POST (403 CSRF) unless CSRF_TRUSTED_ORIGINS lists the real public
# domain(s). Enabling this safely needs the deployment's real domain configured
# in CSRF_TRUSTED_ORIGINS + a verified login flow — staged for review, not on by
# default. nginx still owns the http->https redirect; it can also emit HSTS.
SURICATOOS_BEHIND_TLS_PROXY = env.bool('SURICATOOS_BEHIND_TLS_PROXY', default=False)
if SURICATOOS_BEHIND_TLS_PROXY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
# A04-3/A07-3: login brute-force throttle (custom cache-based; see Suricatoos/login_throttle.py).
# Env-flagged so dev/HTTP and the CI test runner are untouched when off. Behind the nginx
# proxy, resolve_client_ip trusts X-Real-IP (gated on SURICATOOS_BEHIND_TLS_PROXY above).
SURICATOOS_LOGIN_THROTTLE_ENABLED = env.bool('SURICATOOS_LOGIN_THROTTLE_ENABLED', default=not DEBUG)
# Trust nginx's X-Real-IP for the throttle's client-IP bucketing. DECOUPLED from
# SURICATOOS_BEHIND_TLS_PROXY on purpose: that flag also enables SECURE_PROXY_SSL_HEADER
# (CSRF-coupled, off by default), whereas trusting X-Real-IP for IP bucketing is safe
# behind nginx. Default not DEBUG so prod (behind nginx, :8000 internal-only) keys on the
# real client IP and never collapses all clients onto nginx's IP. Set 0 if the app is
# exposed directly without a trusted proxy.
SURICATOOS_LOGIN_TRUST_PROXY_IP = env.bool('SURICATOOS_LOGIN_TRUST_PROXY_IP', default=not DEBUG)
SURICATOOS_LOGIN_FAIL_LIMIT = env.int('SURICATOOS_LOGIN_FAIL_LIMIT', default=5)
SURICATOOS_LOGIN_IP_FAIL_LIMIT = env.int('SURICATOOS_LOGIN_IP_FAIL_LIMIT', default=20)
SURICATOOS_LOGIN_COOLDOWN = env.int('SURICATOOS_LOGIN_COOLDOWN', default=900)  # seconds (sliding lock TTL)
# A07-4: bound the session lifetime (default 14 days is too long for an admin tool
# that stores 3rd-party API keys). Default 8h; env-overridable.
SESSION_COOKIE_AGE = env.int('SESSION_COOKIE_AGE', default=28800)
SESSION_EXPIRE_AT_BROWSER_CLOSE = env.bool('SESSION_EXPIRE_AT_BROWSER_CLOSE', default=False)
# A05-1: baseline Content-Security-Policy emitted by ContentSecurityPolicyMiddleware.
# Safe subset that does not require touching inline scripts; env-overridable.
CONTENT_SECURITY_POLICY = env(
    'SURICATOOS_CSP',
    default="object-src 'none'; base-uri 'self'; frame-ancestors 'none'")

# Suricatoos version
# reads current version from a file called .version
VERSION_FILE = os.path.join(BASE_DIR, '.version')
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, 'r') as f:
        _version = f.read().strip()
else:
    _version = 'unknown'

# removes v from _version if exists
if _version.startswith('v'):
    _version = _version[1:]

SURICATOOS_CURRENT_VERSION = _version

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'recon_note.apps.ReconNoteConfig',
    'django_ace',
    'django_celery_beat',
    'mathfilters',
    'drf_yasg',
    'rolepermissions'
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'Suricatoos.login_throttle.LoginThrottleMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Suricatoos.middleware.ContentSecurityPolicyMiddleware',
    'Suricatoos.middleware.UserPreferencesMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [(os.path.join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'Suricatoos.context_processors.projects',
                'Suricatoos.context_processors.version_context',
                'Suricatoos.context_processors.user_preferences',
                'Suricatoos.context_processors.branding',
            ],
    },
}]
ROOT_URLCONF = 'Suricatoos.urls'
REST_FRAMEWORK = {
    # Session auth: the template-driven (DataTables) API calls authenticate with
    # the logged-in Django session cookie.
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
    ),
    # /api/ is exempted from LoginRequiredMiddleware below so DRF returns proper
    # 401/403 JSON instead of a 302 to /login; require auth at the DRF layer
    # instead so endpoints without an explicit permission_classes are never public.
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':(
        'rest_framework_datatables.pagination.DatatablesPageNumberPagination'
    ),
    'PAGE_SIZE': 500,
}

WSGI_APPLICATION = 'Suricatoos.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Languages the UI is translated into. English is the base (msgid) language;
# pt-br and es are full catalogs. Native names are shown in the language switcher.
LANGUAGES = [
    ('en', 'English'),
    ('pt-br', 'Português (Brasil)'),
    ('es', 'Español'),
]
# Project-level catalog (web/locale/<lang>/LC_MESSAGES/django.po|.mo).
LOCALE_PATHS = [os.path.join(BASE_DIR, 'locale')]

MEDIA_URL = '/media/'
MEDIA_ROOT = '/usr/src/scan_results/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
    # White-label logo/favicon must render on the unauthenticated login page.
    # The view serves only files referenced by the branding model (no path
    # traversal), so exposing it without a session is safe.
    'branding_asset',
]

# Let DRF own auth on the whole API surface: LoginRequiredMiddleware would 302
# API calls to /login before DRF auth runs. DEFAULT_PERMISSION_CLASSES
# (IsAuthenticated) keeps these endpoints protected at the DRF layer.
LOGIN_REQUIRED_IGNORE_PATHS = [
    r'^/api/.*$',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'onboarding'
LOGOUT_REDIRECT_URL = 'login'

# Tool Location
TOOL_LOCATION = '/usr/src/app/tools/'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

'''
CELERY settings
'''
CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Reliability backstops (prefork pool): a hung/killed worker must not leave a task ACTIVE
# forever (the scan-#19 wedge). soft limit lets a task clean up; hard limit SIGKILLs and
# ACKs it (TimeLimitExceeded is not WorkerLostError, so it is NOT requeued). We deliberately
# keep acks_late at its default (False/early-ack): the scan orchestrator tasks
# (subdomain_discovery/osint/port_scan/fetch_url/vulnerability_scan) are NOT idempotent —
# re-running one duplicates ScanActivity rows and re-spawns tools — so a dead worker must
# DROP its task, not redeliver it. The hang itself is already prevented by the run_command/
# stream_command watchdog (which also covers the gevent OSINT pool, where SIGALRM limits are
# a no-op). prefetch=1 stops a worker hoarding long scan tasks; max_tasks/max_memory_per_child
# recycle bloated prefork children between tasks.
# Capacity-proportional: when the env is explicitly set the operator means an
# absolute value (used verbatim); otherwise the default is scaled by the machine
# capacity factor. Uniform scaling keeps soft < hard and budget < soft at any
# factor; on the baseline 2-CPU box the factor is 1.0 so these stay 5400/7200.
# capacity.py imports only os -> no circular import with settings.
from Suricatoos.capacity import scale_timer as _scale_timer
_raw_soft = os.environ.get("CELERY_TASK_SOFT_TIME_LIMIT")
CELERY_TASK_SOFT_TIME_LIMIT = (
    env.int("CELERY_TASK_SOFT_TIME_LIMIT") if _raw_soft not in (None, "")
    else _scale_timer(5400)
)   # 90 min
_raw_hard = os.environ.get("CELERY_TASK_TIME_LIMIT")
CELERY_TASK_TIME_LIMIT = (
    env.int("CELERY_TASK_TIME_LIMIT") if _raw_hard not in (None, "")
    else _scale_timer(7200)
)             # 120 min hard
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = env.int("CELERY_WORKER_MAX_TASKS_PER_CHILD", default=50)
CELERY_WORKER_MAX_MEMORY_PER_CHILD = env.int("CELERY_WORKER_MAX_MEMORY_PER_CHILD", default=350000)  # KB (~350MB)

# Periodic backstop: sweep for silently-wedged scans (RUNNING with no recent
# activity) and auto-abort them. django_celery_beat's DatabaseScheduler syncs this
# dict into its DB tables on beat startup, so no migration/manual entry is needed.
CELERY_BEAT_SCHEDULE = {
    'hang-monitor': {
        'task': 'hang_monitor',
        'schedule': env.float("HANG_MONITOR_INTERVAL", default=600.0),  # every 10 min
        'options': {'queue': 'hang_monitor_queue', 'expires': 540},
    },
}
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'Suricatoos.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
SURICATOOS_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': 'errors.log',
        },
        'null': {
            'class': 'logging.NullHandler'
        },
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'brief': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task'
        },
        'db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': 'db.log',
            'maxBytes': 1024,
            'backupCount': 3
        },
        'celery': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': 'celery.log',
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
        },
    },
    'formatters': {
        'default': {
            'format': '%(message)s'
        },
        'brief': {
            'format': '%(name)-10s | %(message)s'
        },
        'task': {
            '()': lambda : SuricatoosTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s')
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
            'datefmt': '%y %b %d, %H:%M:%S',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR' if DEBUG else 'CRITICAL',
            'propagate': True,
        },
        '': {
            'handlers': ['brief'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'celery': {
            'handlers': ['celery'],
            'level': 'DEBUG' if DEBUG else 'ERROR',
        },
        'celery.app.trace': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['task'],
            'propagate': False
        },
        'celery.worker': {
            'handlers': ['null'],
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db'],
            'level': 'INFO',
            'propagate': False
        },
        'Suricatoos.tasks': {
            'handlers': ['task'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'api.views': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        }
    },
}

'''
File upload settings
'''
DATA_UPLOAD_MAX_NUMBER_FIELDS = None

'''
    Caching Settings
'''
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'TIMEOUT': 60 * 30,  # 30 minutes caching will be used
    },
    # A04-3: dedicated alias for the login throttle so its counters don't share an LRU
    # with scan-result caching. LocMemCache is correct for the current single web process;
    # multi-worker/replica deployments should point this at a shared store (Redis via
    # django-redis) — login_throttle._throttle_cache() logs a warning while it's LocMem.
    'login_throttle': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'suricatoos-login-throttle',
        'TIMEOUT': SURICATOOS_LOGIN_COOLDOWN,
    },
}