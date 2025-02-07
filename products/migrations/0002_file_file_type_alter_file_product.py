# Generated by Django 4.2 on 2025-02-07 17:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("products", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="file",
            name="file_type",
            field=models.PositiveSmallIntegerField(
                choices=[(1, "Audio"), (2, "Video"), (3, "PDF")],
                default=2,
                verbose_name="file type",
            ),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="file",
            name="product",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="files",
                to="products.product",
                verbose_name="product",
            ),
        ),
    ]
