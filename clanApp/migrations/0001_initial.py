# Generated by Django 5.0.3 on 2024-03-28 11:18

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Residence",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("address", models.TextField()),
                ("region", models.CharField(max_length=100)),
                ("district", models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name="Person",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("first_name", models.CharField(max_length=100)),
                ("middle_name", models.CharField(max_length=100)),
                ("surname", models.CharField(max_length=100)),
                ("nickname", models.CharField(max_length=100)),
                ("date_of_birth", models.DateField(verbose_name="")),
                ("email", models.EmailField(max_length=254)),
                ("spouse", models.CharField(max_length=100)),
                ("marital_status", models.CharField(max_length=100)),
                ("marriage_registered", models.BooleanField()),
                (
                    "residence_status",
                    models.CharField(
                        choices=[
                            ("In Tanzania", "In Tanzania"),
                            ("Outside Tanzania", "Outside Tanzania"),
                        ],
                        max_length=100,
                    ),
                ),
                ("country_of_residence", models.CharField(max_length=100)),
                ("phone", models.CharField(max_length=10)),
                ("address", models.TextField()),
                (
                    "sex",
                    models.CharField(
                        choices=[("Male", "Male"), ("Female", "Female")], max_length=6
                    ),
                ),
                (
                    "parent",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="clanApp.person",
                    ),
                ),
            ],
        ),
    ]
