from django.urls import path

from .views import (
    ForgotPasswordView,
    LoginView,
    LogoutView,
    MeView,
    RegisterView,
    RegistrationCodeIssueView,
    RegistrationCodeVerifyView,
    ResetPasswordView,
)

urlpatterns = [
    path("login/", LoginView.as_view(), name="auth-login"),
    path("logout/", LogoutView.as_view(), name="auth-logout"),
    path("me/", MeView.as_view(), name="auth-me"),
    # Self-service sign-up, in the order the console asks for it: address, code,
    # then the account. Each one is unauthenticated and rate-limited on its own.
    path("register-code/", RegistrationCodeIssueView.as_view(), name="register-code-issue"),
    path("register-code-verify/", RegistrationCodeVerifyView.as_view(), name="register-code-verify"),
    path("register/", RegisterView.as_view(), name="register"),
    # Password reset: a link to the address on file, then the new password.
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset-password"),
]
