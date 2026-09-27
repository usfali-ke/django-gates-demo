"""gunicorn settings. Migrations run once, in the master, before workers
fork — the image has no shell entrypoint to do it."""

import tempfile

bind = "0.0.0.0:8000"
workers = 2
threads = 4
# The image's temp dir (HOME=/tmp): a private tmpfs/emptyDir, since the root
# filesystem is read-only.
worker_tmp_dir = tempfile.gettempdir()
accesslog = "-"
forwarded_allow_ips = "*"  # only the ingress/proxy can reach the pod port
wsgi_app = "config.wsgi:application"


def on_starting(server):
    import os

    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import call_command

    django.setup()
    call_command("migrate", interactive=False, verbosity=1)
