from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class MasterPassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    master_hash = models.CharField(max_length=255)


class PasswordEntry(models.Model):
    CATEGORY_CHOICES = [
        ('personal', 'Personal'),
        ('work',     'Work'),
        ('banking',  'Banking'),
        ('social',   'Social'),
        ('other',    'Other'),
    ]

    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    title      = models.CharField(max_length=100)
    username   = models.CharField(max_length=100)
    email      = models.EmailField(blank=True)
    password   = models.BinaryField()
    category   = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class LoginAttempt(models.Model):
    """Tracks failed login attempts per username for lockout."""
    username    = models.CharField(max_length=150, db_index=True)
    attempts    = models.IntegerField(default=0)
    locked_until= models.DateTimeField(null=True, blank=True)
    last_attempt= models.DateTimeField(auto_now=True)

    def is_locked(self):
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False

    def reset(self):
        self.attempts = 0
        self.locked_until = None
        self.save()


class OTPToken(models.Model):
    """Stores OTP for 2FA after login."""
    user       = models.OneToOneField(User, on_delete=models.CASCADE)
    token      = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now=True)
    verified   = models.BooleanField(default=False)

    def is_expired(self):
        from django.conf import settings
        expiry_minutes = 10
        return (timezone.now() - self.created_at).seconds > expiry_minutes * 60
