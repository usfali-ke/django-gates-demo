from django.urls import path

from . import views

app_name = "notes"
urlpatterns = [
    path("notes/", views.note_list, name="list"),
    path("notes/<int:pk>/delete/", views.note_delete, name="delete"),
    path("api/notes/", views.api_notes, name="api-list"),
    path("api/notes/<int:pk>/", views.api_note_detail, name="api-detail"),
]
