from django.urls import path

from .views import (
    ChangePasswordView,
    ForgotPasswordView,
    LoginView,
    LogoutView,
    MeView,
    RegisterView,
    RegistrationCodeIssueView,
    RegistrationCodeVerifyView,
    ResetPasswordView,
    SessionListView,
    SessionRevokeView,
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
    # Self-service account and security. A PATCH on /me/ rather than a separate
    # profile endpoint: the payload is the same user object the page already
    # fetched, and one endpoint per record is what keeps the two from drifting.
    path("change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("sessions/", SessionListView.as_view(), name="session-list"),
    path("sessions/<str:jti>/", SessionRevokeView.as_view(), name="session-revoke"),
]
