# Generated by Django 5.1.1 on 2024-09-04 19:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Passwords',
            fields=[
                ('password_id', models.AutoField(primary_key=True, serialize=False)),
                ('platform', models.CharField(max_length=50)),
                ('website', models.CharField(max_length=50)),
                ('username', models.CharField(max_length=32)),
                ('email', models.EmailField(max_length=100, unique=True)),
                ('password', models.CharField(max_length=32)),
            ],
        ),
        migrations.DeleteModel(
            name='User',
        ),
    ]
