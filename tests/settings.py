"""The production settings, plus only what a test run needs to import them."""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "unit-tests-only-" + "x" * 50)
os.environ.setdefault("DJANGO_DB_PATH", ":memory:")

from config.settings import *  # noqa: E402,F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # fast; tests only
# The manifest is written by collectstatic in the image build; tests don't run it.
STORAGES = {**STORAGES, "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}  # noqa: F405
WHITENOISE_AUTOREFRESH = True  # serve from finders; no staticfiles/ dir in tests
