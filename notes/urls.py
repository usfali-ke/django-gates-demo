from django.urls import path

from . import search, stats, views

app_name = "notes"
urlpatterns = [
    path("notes/", views.note_list, name="list"),
    path("notes/<int:pk>/delete/", views.note_delete, name="delete"),
    path("api/notes/", views.api_notes, name="api-list"),
    path("api/notes/<int:pk>/", views.api_note_detail, name="api-detail"),
    path("notes/search/", search.search, name="search"),
    path("notes/<int:pk>/export/", search.export_note, name="export"),
    path("notes/export/archive/", search.export_archive, name="export-archive"),
    path("notes/attachment/", search.attachment, name="attachment"),
    path("notes/stats/daily/", stats.daily_counts, name="stats-daily"),
]
