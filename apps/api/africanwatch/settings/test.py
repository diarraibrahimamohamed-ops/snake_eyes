from .base import *
DEBUG = False
SECRET_KEY = "test-key-not-for-production"
DATABASES = {"default":{"ENGINE":"django.db.backends.postgresql","NAME":env("POSTGRES_DB",default="africanwatch_test"),"USER":env("POSTGRES_USER",default="aw_user"),"PASSWORD":env("POSTGRES_PASSWORD",default="test_password"),"HOST":env("POSTGRES_HOST",default="localhost"),"PORT":"5432"}}
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CHANNEL_LAYERS = {"default":{"BACKEND":"channels.layers.InMemoryChannelLayer"}}
