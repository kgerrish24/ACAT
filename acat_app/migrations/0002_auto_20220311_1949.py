# Generated by Django 3.2.9 on 2022-03-12 00:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('acat_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Main_Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Category', models.CharField(max_length=100, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Sub_Settings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Sub_Setting', models.CharField(max_length=100)),
                ('Sub_Value', models.CharField(max_length=100)),
                ('Cat', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='acat_app.main_category')),
            ],
            options={
                'ordering': ['Sub_Setting'],
            },
        ),
        migrations.DeleteModel(
            name='X509v3_Extension_Templates',
        ),
    ]
