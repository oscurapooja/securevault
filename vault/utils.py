import hashlib
import random
import requests
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from cryptography.fernet import Fernet

cipher = Fernet(settings.VAULT_KEY)

# ── Master password helpers ──
def hash_master(password):
    return make_password(password)

def verify_master(password, hashed):
    return check_password(password, hashed)

# ── Vault encryption ──
def encrypt_password(text):
    return cipher.encrypt(text.encode())

def decrypt_password(token):
    return cipher.decrypt(token).decode()

# ── HIBP breach check ──
def is_pwned_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if res.status_code != 200:
            return False
        return any(h == suffix for h, _ in (line.split(':') for line in res.text.splitlines()))
    except Exception:
        return False

# ── OTP generation ──
def generate_otp():
    return str(random.randint(100000, 999999))

# ── Password strength ──
def password_strength(pw):
    """Returns (score 0-4, label, color)"""
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 14: score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() or c in '!@#$%^&*' for c in pw): score += 1
    labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
    colors = ['danger', 'danger', 'warning', 'success', 'success']
    return score, labels[score], colors[score]
