# ACAT/ACAT/acat_app/apps.py


from django.apps import AppConfig
import acat_app.app_settings as appset


class AcatAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "acat_app"
