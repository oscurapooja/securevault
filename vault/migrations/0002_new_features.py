from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0001_initial'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        # Add category to PasswordEntry
        migrations.AddField(
            model_name='passwordentry',
            name='category',
            field=models.CharField(
                choices=[('personal','Personal'),('work','Work'),('banking','Banking'),('social','Social'),('other','Other')],
                default='other', max_length=20,
            ),
        ),
        # Add updated_at to PasswordEntry
        migrations.AddField(
            model_name='passwordentry',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        # LoginAttempt model
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('username', models.CharField(db_index=True, max_length=150)),
                ('attempts', models.IntegerField(default=0)),
                ('locked_until', models.DateTimeField(blank=True, null=True)),
                ('last_attempt', models.DateTimeField(auto_now=True)),
            ],
        ),
        # OTPToken model
        migrations.CreateModel(
            name='OTPToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('token', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now=True)),
                ('verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='auth.user')),
            ],
        ),
    ]
