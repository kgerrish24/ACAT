# ACAT/ACAT/acat_app/urls.py

from django.urls import path
import acat_app.app_settings as appset
from .views import about, app_settings, examine, file_hash, generate_Certificate, genkeypair, index, messaging, upload


urlpatterns = [
    # page view name
    path("", index, name="index"),
    path("about", about, name="about"),
    path("app_settings", app_settings, name="app_settings"),
    path("examine", examine, name="examine"),
    path("file_hash", file_hash, name="file_hash"),
    path("genkeypair", genkeypair, name="genkeypair"),
    path("generate_certificate", generate_Certificate,
         name="generate_certificate"),
    path("index", index, name="index"),
    path("messaging", messaging, name="messaging"),
    path("upload", upload, name="upload"),
]
