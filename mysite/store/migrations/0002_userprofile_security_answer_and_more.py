# Generated by Django 5.1.7 on 2025-03-12 09:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='security_answer',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='security_question',
            field=models.CharField(default="What is your mother's maiden name?", max_length=200),
        ),
    ]
