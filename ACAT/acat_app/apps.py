# ACAT/ACAT/acat_app/apps.py


from django.apps import AppConfig
from .app_settings import *


class AcatAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "acat_app"
