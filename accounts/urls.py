from django.contrib.auth import views as auth_views
from django.urls import path

from . import views
from .forms import ApprovedMemberAuthenticationForm

urlpatterns = [
    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="accounts/login.html",
            authentication_form=ApprovedMemberAuthenticationForm,
        ),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("register/", views.register, name="member-register"),
    path("profile/", views.member_profile, name="member-profile"),
    path("settings/", views.account_settings, name="account-settings"),
]
