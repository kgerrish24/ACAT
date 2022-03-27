# ACAT/ACAT/acat_app/urls.py

from django.urls import path

from .global_ import *
from .views import (
    about,
    examine,
    file_hash,
    generate_Certificate,
    genkeypair,
    index,
    messaging,
    new_design,
    test_view,
    upload,
)

urlpatterns = [
    # page view name
    path("", index, name="index"),
    path("about", about, name="about"),
    path("examine", examine, name="examine"),
    path("file_hash", file_hash, name="file_hash"),
    path("genkeypair", genkeypair, name="genkeypair"),
    path("generate_certificate", generate_Certificate, name="generate_certificate"),
    path("index", index, name="index"),
    path("messaging", messaging, name="messaging"),
    path("new_design", new_design, name="new_design"),
    path("test_view", test_view),
    path("upload", upload, name="upload"),
]
