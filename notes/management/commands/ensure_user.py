"""Create or update a login from the environment, never from argv (so the
password doesn't land in shell history or `ps`).

    ENSURE_USER_PASSWORD=... python manage.py ensure_user alice
"""

import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create or update a user; the password comes from ENSURE_USER_PASSWORD."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, username, **options):
        password = os.environ.get("ENSURE_USER_PASSWORD")
        if not password:
            raise CommandError("ENSURE_USER_PASSWORD is not set")
        user, created = get_user_model().objects.get_or_create(username=username)
        validate_password(password, user)
        user.set_password(password)
        user.save()
        self.stdout.write(f"{'created' if created else 'updated'} {username}")
