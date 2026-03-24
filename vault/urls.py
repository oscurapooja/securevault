from django.urls import path
from . import views

urlpatterns = [
    path('',                        views.login_view,      name='login'),
    path('register/',               views.register_view,   name='register'),
    path('verify-otp/',             views.verify_otp_view, name='verify_otp'),
    path('resend-otp/',             views.resend_otp_view, name='resend_otp'),
    path('dashboard/',              views.dashboard,       name='dashboard'),
    path('add/',                    views.add_password,    name='add'),
    path('view/',                   views.view_passwords,  name='view'),
    path('edit/<int:entry_id>/',    views.edit_password,   name='edit'),
    path('delete/<int:entry_id>/',  views.delete_password, name='delete'),
    path('logout/',                 views.logout_view,     name='logout'),
    path('check-breach/',           views.check_breach,    name='check_breach'),
    path('security-audit/',         views.security_audit,  name='security_audit'),
]
