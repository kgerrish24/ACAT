# Generated by Django 4.0.3 on 2022-03-14 02:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acat_app', '0009_subattrib_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='commonnamelist',
            name='commonname',
            field=models.CharField(auto_created=True, max_length=100, unique=True),
        ),
    ]
