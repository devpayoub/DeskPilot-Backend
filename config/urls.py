from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.evals.views import StatsView
from apps.guardrails.views import health, ToolListView, ToolInvokeView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/health/", health, name="health"),
    # Console auth: the BFF exchanges credentials here and stores the tokens in
    # httpOnly cookies. `/auth/token/` remains for the CLI and the test suite.
    path("api/v1/auth/", include("apps.accounts.urls")),
    path("api/v1/auth/token/", TokenObtainPairView.as_view(), name="token-obtain"),
    path("api/v1/auth/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("api/v1/stats/", StatsView.as_view(), name="stats"),
    path("api/v1/evals/", include("apps.evals.urls")),
    path("api/v1/tools/", ToolListView.as_view(), name="tool-list"),
    path("api/v1/tools/<str:name>/invoke/", ToolInvokeView.as_view(), name="tool-invoke"),
    path("api/v1/", include("apps.agent.urls")),
    path("api/v1/directory/", include("apps.directory.urls")),
    path("api/v1/org/", include("apps.organizations.urls")),
    path("api/v1/guardrails/", include("apps.guardrails.urls")),
    path("api/v1/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/v1/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]
