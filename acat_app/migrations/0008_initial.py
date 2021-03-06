# Generated by Django 4.0.3 on 2022-03-14 01:42

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('acat_app', '0007_delete_acat_settings'),
    ]

    operations = [
        migrations.CreateModel(
            name='CommonNameList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('commonname', models.CharField(max_length=100, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='SubAttrib',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.CharField(max_length=100)),
                ('organizational_unit', models.CharField(max_length=100)),
                ('locality', models.CharField(max_length=100)),
                ('state', models.CharField(max_length=100)),
                ('country', models.CharField(max_length=100)),
                ('common_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='acat_app.commonnamelist')),
            ],
        ),
    ]
