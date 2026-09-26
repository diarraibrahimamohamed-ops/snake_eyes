"""AfricaWatch — Base Settings"""
import os
from datetime import timedelta
from pathlib import Path
import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env = environ.Env()
_env = BASE_DIR.parent.parent / ".env"
if _env.exists():
    environ.Env.read_env(str(_env))

SECRET_KEY = env("SECRET_KEY", default="dev-only-key-not-for-production-CHANGE-ME")
AI_ENABLED = env.bool("AI_ENABLED", default=False)
AI_MAX_INPUT_CHARS = env.int("AI_MAX_INPUT_CHARS", default=12000)
AI_MAX_OUTPUT_TOKENS = env.int("AI_MAX_OUTPUT_TOKENS", default=384)
AI_TIMEOUT_SECONDS = env.int("AI_TIMEOUT_SECONDS", default=15)
AI_MODEL = env("AI_MODEL", default="qwen2.5:1.5b-instruct-q3_K_S")
LAB_MODE = env.bool("LAB_MODE", default=False)
SECURITY_ASSESSMENT_MAX_RUNTIME = env.int("SECURITY_ASSESSMENT_MAX_RUNTIME", default=180)
SECURITY_ASSESSMENT_KILL_SWITCH = env.bool("SECURITY_ASSESSMENT_KILL_SWITCH", default=False)
SECURITY_ASSESSMENT_CONCURRENCY_RETRY_SECONDS = env.int("SECURITY_ASSESSMENT_CONCURRENCY_RETRY_SECONDS", default=5)
ALLOWED_PUBLIC_TARGET_PORTS = [int(value) for value in env.list("ALLOWED_PUBLIC_TARGET_PORTS", default=["80", "443", "8080", "8443"]) if str(value).isdigit()]
ALLOWED_HOSTS = env("ALLOWED_HOSTS", default="localhost,127.0.0.1,0.0.0.0").split(",")

# Security assessment lab: all sensitive inputs stay server-side; API receives profile names only.
SECURITY_CODE_ROOT = env("SECURITY_CODE_ROOT", default="/security-lab/code")
SECURITY_CONTAINER_ROOT = env("SECURITY_CONTAINER_ROOT", default="/security-lab/containers")
CREDENTIAL_LAB_ROOT = env("CREDENTIAL_LAB_ROOT", default="/security-lab/credentials")
CREDENTIAL_WORDLIST_ROOT = env("CREDENTIAL_WORDLIST_ROOT", default="/security-lab/wordlists")
ALLOW_LOCAL_CREDENTIAL_AUDIT = env.bool("ALLOW_LOCAL_CREDENTIAL_AUDIT", default=False)
SECURITY_LAB_MAX_RUNTIME = env.int("SECURITY_LAB_MAX_RUNTIME", default=300)
ONION_ALLOWED_HOSTS = [x.strip().lower() for x in env.list("ONION_ALLOWED_HOSTS", default=[]) if x.strip()]
TOR_SOCKS_PROXY = env("TOR_SOCKS_PROXY", default="socks5://tor:9050")
TOR_ENABLED = env.bool("TOR_ENABLED", default=False)
TOR_PASSIVE_ONLY = env.bool("TOR_PASSIVE_ONLY", default=True)
MALWARE_MAX_UPLOAD_BYTES = env.int("MALWARE_MAX_UPLOAD_BYTES", default=25 * 1024 * 1024)
MALWARE_QUARANTINE_ROOT = env("MALWARE_QUARANTINE_ROOT", default="/security-lab/quarantine")
MALWARE_SCANNER_DAEMON_ENABLED = env.bool("MALWARE_SCANNER_DAEMON_ENABLED", default=True)
MALWARE_SCAN_JOBS_ROOT = env("MALWARE_SCAN_JOBS_ROOT", default="/security-lab/jobs")
MALWARE_SCAN_RESULTS_ROOT = env("MALWARE_SCAN_RESULTS_ROOT", default="/security-lab/results")
MALWARE_YARA_RULES = env("MALWARE_YARA_RULES", default="/security-lab/yara/africanwatch.yar")
INTEL_MAX_SOURCES_PER_RUN = env.int("INTEL_MAX_SOURCES_PER_RUN", default=12)
INTEL_MAX_OBSERVATIONS_PER_RUN = env.int("INTEL_MAX_OBSERVATIONS_PER_RUN", default=100)
INTEL_ENABLE_GDELT = env.bool("INTEL_ENABLE_GDELT", default=True)
OSINT_SPACY_ENABLED = env.bool("OSINT_SPACY_ENABLED", default=False)
OSINT_EXTERNAL_TRANSLATION_ENABLED = env.bool("OSINT_EXTERNAL_TRANSLATION_ENABLED", default=False)

DJANGO_APPS = [
    "django.contrib.admin","django.contrib.auth","django.contrib.contenttypes",
    "django.contrib.sessions","django.contrib.messages","django.contrib.staticfiles",
]
THIRD_PARTY_APPS = [
    "rest_framework","rest_framework_simplejwt","rest_framework_simplejwt.token_blacklist",
    "corsheaders","django_filters","django_extensions","drf_spectacular",
    "channels","django_celery_beat","django_celery_results","axes","django_prometheus",
]
LOCAL_APPS = [
    "africanwatch.apps.organizations","africanwatch.apps.threat_intel",
    "africanwatch.apps.osint","africanwatch.apps.soc","africanwatch.apps.vulns",
    "africanwatch.apps.ai_engine","africanwatch.apps.dashboard",
    "africanwatch.apps.offensive_lab", "africanwatch.apps.security_lab",
    "africanwatch.apps.intelligence", "africanwatch.apps.malware_lab",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
    "africanwatch.middleware.AuditLogMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

ROOT_URLCONF = "africanwatch.urls"
WSGI_APPLICATION = "africanwatch.wsgi.application"
ASGI_APPLICATION = "africanwatch.asgi.application"
AUTH_USER_MODEL = "organizations.User"

DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": env("POSTGRES_DB", default="africanwatch"),
    "USER": env("POSTGRES_USER", default="aw_user"),
    "PASSWORD": env("POSTGRES_PASSWORD", default="changeme_dev"),
    "HOST": env("POSTGRES_HOST", default="postgres"),
    "PORT": env("POSTGRES_PORT", default="5432"),
    "CONN_MAX_AGE": 60,
}}

REDIS_URL = env("REDIS_URL", default="redis://redis:6379/0")
CACHES = {"default": {
    "BACKEND": "django_redis.cache.RedisCache",
    "LOCATION": REDIS_URL,
    "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient", "IGNORE_EXCEPTIONS": True},
}}
CHANNEL_LAYERS = {"default": {"BACKEND": "channels_redis.core.RedisChannelLayer", "CONFIG": {"hosts": [REDIS_URL]}}}

CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = "django-db"
CELERY_CACHE_BACKEND = "django-cache"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework_simplejwt.authentication.JWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "africanwatch.pagination.StandardPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle","rest_framework.throttling.UserRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"anon": "100/hour","user": "10000/hour"},
    "EXCEPTION_HANDLER": "africanwatch.exceptions.custom_exception_handler",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "AUTH_HEADER_TYPES": ("Bearer",),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "AfricaWatch API",
    "DESCRIPTION": "Plateforme africaine de cybersécurité, threat intelligence & OSINT",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=["http://localhost:3000","http://127.0.0.1:3000"])
CORS_ALLOW_CREDENTIALS = True

AUTHENTICATION_BACKENDS = ["axes.backends.AxesStandaloneBackend","django.contrib.auth.backends.ModelBackend"]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator","OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_LOCKOUT_CALLABLE = "africanwatch.exceptions.lockout_response"
AXES_RESET_ON_SUCCESS = True

ELASTICSEARCH_URL = env("ELASTICSEARCH_URL", default="")
KAFKA_BOOTSTRAP_SERVERS = env("KAFKA_BOOTSTRAP_SERVERS", default="")
KAFKA_TOPICS = {
    "IOC_CREATED":"aw.ioc.created","IOC_UPDATED":"aw.ioc.updated",
    "ALERT_CREATED":"aw.alert.created","INCIDENT_UPDATED":"aw.incident.updated",
    "OSINT_EVENT":"aw.osint.event","VULN_DISCOVERED":"aw.vuln.discovered",
}

VIRUSTOTAL_API_KEY = env("VIRUSTOTAL_API_KEY", default="")
SHODAN_API_KEY = env("SHODAN_API_KEY", default="")
OTX_API_KEY = env("OTX_API_KEY", default="")
MISP_URL = env("MISP_URL", default="")
MISP_KEY = env("MISP_KEY", default="")
GEOIP_PATH = env("GEOIP_PATH", default="/app/data/geoip")
OLLAMA_URL = env("OLLAMA_URL", default="http://ollama:11434")
OLLAMA_MODEL = AI_MODEL
AFRICAS_TALKING_API_KEY = env("AFRICAS_TALKING_API_KEY", default="")
AFRICAS_TALKING_USERNAME = env("AFRICAS_TALKING_USERNAME", default="sandbox")

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = []
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LANGUAGE_CODE = "fr-FR"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

TEMPLATES = [{"BACKEND":"django.template.backends.django.DjangoTemplates","DIRS":[BASE_DIR/"templates"],"APP_DIRS":True,"OPTIONS":{"context_processors":["django.template.context_processors.debug","django.template.context_processors.request","django.contrib.auth.context_processors.auth","django.contrib.messages.context_processors.messages"]}}]

LOGGING = {
    "version": 1,"disable_existing_loggers": False,
    "formatters": {"verbose": {"format": "[{levelname}] {asctime} {module} — {message}","style": "{"}},
    "handlers": {"console": {"class": "logging.StreamHandler","formatter": "verbose"}},
    "root": {"handlers": ["console"],"level": "INFO"},
    "loggers": {"africanwatch": {"handlers": ["console"],"level": "DEBUG","propagate": False}},
}
