from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from .models import MasterPassword, PasswordEntry, LoginAttempt, OTPToken
from .utils import (hash_master, verify_master, encrypt_password,
                    decrypt_password, is_pwned_password,
                    generate_otp, password_strength)


# ══════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════
def get_login_attempt(username):
    obj, _ = LoginAttempt.objects.get_or_create(username=username)
    return obj

def record_failed_login(username):
    obj = get_login_attempt(username)
    if obj.is_locked():
        return obj
    obj.attempts += 1
    if obj.attempts >= settings.MAX_LOGIN_ATTEMPTS:
        obj.locked_until = timezone.now() + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
    obj.save()
    return obj

def send_otp_email(user, otp):
    subject = '🔐 Your Secure Vault OTP Code'
    body = f"""Hi {user.username},

Your One-Time Password (OTP) for Secure Vault login is:

    {otp}

This code expires in 10 minutes. Do not share it with anyone.

— Secure Vault Security Team
"""
    # Console backend prints to terminal; swap settings for real SMTP
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL,
              [user.email], fail_silently=True)


# ══════════════════════════════════════════
#  AUTH VIEWS
# ══════════════════════════════════════════
def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email    = request.POST['email']
        password = request.POST['password']
        confirm  = request.POST['confirm']
        master   = request.POST['master']

        if password != confirm:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return redirect('register')
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password)
        MasterPassword.objects.create(user=user, master_hash=hash_master(master))
        messages.success(request, 'Account created! Please sign in.')
        return redirect('login')

    return render(request, 'register.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        attempt = get_login_attempt(username)

        # Check lockout
        if attempt.is_locked():
            remaining = int((attempt.locked_until - timezone.now()).total_seconds() // 60) + 1
            messages.error(request, f'Account locked. Try again in {remaining} minute(s).')
            return render(request, 'login.html', {'locked': True, 'remaining': remaining})

        user = authenticate(username=username, password=password)
        if user:
            attempt.reset()

            # Generate & send OTP
            otp = generate_otp()
            OTPToken.objects.update_or_create(user=user, defaults={'token': otp, 'verified': False})
            send_otp_email(user, otp)

            # Store user id in session temporarily (not fully logged in yet)
            request.session['otp_user_id'] = user.id
            messages.info(request, f'OTP sent to {user.email[:3]}***@{user.email.split("@")[1] if "@" in user.email else "your email"}. Check your terminal (demo mode).')
            return redirect('verify_otp')
        else:
            obj = record_failed_login(username)
            remaining_attempts = settings.MAX_LOGIN_ATTEMPTS - obj.attempts
            if obj.is_locked():
                messages.error(request, f'Too many failed attempts. Account locked for {settings.LOCKOUT_DURATION_MINUTES} minutes.')
            else:
                messages.error(request, f'Invalid credentials. {max(remaining_attempts, 0)} attempt(s) remaining.')

    return render(request, 'login.html')


def verify_otp_view(request):
    user_id = request.session.get('otp_user_id')
    if not user_id:
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('login')

    if request.method == 'POST':
        entered = request.POST.get('otp', '').strip()
        try:
            otp_obj = OTPToken.objects.get(user=user)
        except OTPToken.DoesNotExist:
            messages.error(request, 'OTP not found. Please login again.')
            return redirect('login')

        if otp_obj.is_expired():
            messages.error(request, 'OTP has expired. Please login again.')
            del request.session['otp_user_id']
            return redirect('login')

        if otp_obj.token == entered:
            otp_obj.verified = True
            otp_obj.save()
            del request.session['otp_user_id']
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'verify_otp.html', {'email_hint': user.email})


def resend_otp_view(request):
    user_id = request.session.get('otp_user_id')
    if not user_id:
        return redirect('login')
    try:
        user = User.objects.get(id=user_id)
        otp = generate_otp()
        OTPToken.objects.update_or_create(user=user, defaults={'token': otp, 'verified': False})
        send_otp_email(user, otp)
        messages.success(request, 'New OTP sent! Check your terminal.')
    except User.DoesNotExist:
        pass
    return redirect('verify_otp')


def logout_view(request):
    logout(request)
    return redirect('login')


# ══════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════
@login_required
def dashboard(request):
    entries = PasswordEntry.objects.filter(user=request.user)
    entry_count = entries.count()

    # Category counts for sidebar badges
    cat_counts = {}
    for c, _ in PasswordEntry.CATEGORY_CHOICES:
        cat_counts[c] = entries.filter(category=c).count()

    return render(request, 'dashboard.html', {
        'entry_count': entry_count,
        'cat_counts': cat_counts,
    })


# ══════════════════════════════════════════
#  VAULT CRUD
# ══════════════════════════════════════════
@login_required
def add_password(request):
    if request.method == 'POST':
        master = request.POST['master']
        mp = MasterPassword.objects.get(user=request.user)

        if not verify_master(master, mp.master_hash):
            messages.error(request, 'Invalid master password.')
            return render(request, 'add_password.html', {'form_data': request.POST})

        PasswordEntry.objects.create(
            user     = request.user,
            title    = request.POST['title'],
            username = request.POST['username'],
            email    = request.POST.get('email', ''),
            password = encrypt_password(request.POST['password']),
            category = request.POST.get('category', 'other'),
        )
        messages.success(request, f'✅ "{request.POST["title"]}" saved to your vault.')
        return redirect('view')

    return render(request, 'add_password.html')


@login_required
def view_passwords(request):
    category_filter = request.GET.get('cat', 'all')
    entries = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')

    if category_filter != 'all':
        entries = entries.filter(category=category_filter)

    if request.method == 'POST':
        master = request.POST.get('master', '')
        mp = MasterPassword.objects.get(user=request.user)

        if not verify_master(master, mp.master_hash):
            messages.error(request, 'Incorrect master password.')
        else:
            for e in entries:
                e.decrypted = decrypt_password(bytes(e.password))
            return render(request, 'passwords.html', {
                'entries': entries,
                'unlocked': True,
                'category_filter': category_filter,
            })

    for e in entries:
        e.decrypted = None
    return render(request, 'passwords.html', {
        'entries': entries,
        'unlocked': False,
        'category_filter': category_filter,
    })


@login_required
def delete_password(request, entry_id):
    entry = get_object_or_404(PasswordEntry, id=entry_id, user=request.user)
    if request.method == 'POST':
        mp = MasterPassword.objects.get(user=request.user)
        if not verify_master(request.POST.get('master', ''), mp.master_hash):
            messages.error(request, 'Incorrect master password.')
        else:
            title = entry.title
            entry.delete()
            messages.success(request, f'🗑 "{title}" deleted.')
    return redirect('view')


@login_required
def edit_password(request, entry_id):
    entry = get_object_or_404(PasswordEntry, id=entry_id, user=request.user)

    if request.method == 'POST':
        mp = MasterPassword.objects.get(user=request.user)
        if not verify_master(request.POST.get('master', ''), mp.master_hash):
            messages.error(request, 'Incorrect master password.')
            return render(request, 'edit_password.html', {'entry': entry})

        entry.title    = request.POST['title']
        entry.username = request.POST['username']
        entry.email    = request.POST.get('email', '')
        entry.category = request.POST.get('category', entry.category)
        new_pw = request.POST.get('password', '').strip()
        if new_pw:
            entry.password = encrypt_password(new_pw)
        entry.save()
        messages.success(request, f'✅ "{entry.title}" updated.')
        return redirect('view')

    return render(request, 'edit_password.html', {'entry': entry})


# ══════════════════════════════════════════
#  TOOLS
# ══════════════════════════════════════════
@login_required
def check_breach(request):
    if request.method == 'POST':
        password = request.POST.get('password', '')
        if is_pwned_password(password):
            messages.error(request, '⚠️ This password appeared in a known data breach! Change it immediately.')
        else:
            messages.success(request, '✅ This password was NOT found in known breaches. Looks safe!')
    return redirect('dashboard')


@login_required
def security_audit(request):
    """Analyse all vault entries for weak / duplicate passwords."""
    entries = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')

    # Must unlock to audit
    audit_done = False
    weak   = []
    duplicates = []
    strong_count = 0

    if request.method == 'POST':
        mp = MasterPassword.objects.get(user=request.user)
        if not verify_master(request.POST.get('master', ''), mp.master_hash):
            messages.error(request, 'Incorrect master password.')
        else:
            audit_done = True
            pw_map = {}  # decrypted_pw -> [entry titles]

            for e in entries:
                dec = decrypt_password(bytes(e.password))
                e.decrypted = dec
                score, label, color = password_strength(dec)
                e.strength_score = score
                e.strength_label = label
                e.strength_color = color

                if score <= 1:
                    weak.append(e)
                else:
                    strong_count += 1

                pw_map.setdefault(dec, []).append(e)

            # Find duplicates
            for pw, elist in pw_map.items():
                if len(elist) > 1:
                    duplicates.extend(elist)

    return render(request, 'security_audit.html', {
        'entries':      entries,
        'audit_done':   audit_done,
        'weak':         weak,
        'duplicates':   duplicates,
        'strong_count': strong_count,
        'total':        entries.count(),
    })
