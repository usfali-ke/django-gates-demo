from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import RedirectView

from notes import views

# No django.contrib.admin: nothing here needs it, and it is attack surface.
urlpatterns = [
    path("", RedirectView.as_view(pattern_name="notes:list", permanent=False)),
    path("healthz", views.healthz, name="healthz"),
    path("accounts/login/", auth_views.LoginView.as_view(redirect_authenticated_user=True), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("notes.urls")),
]
