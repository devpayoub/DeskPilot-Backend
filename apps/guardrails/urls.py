from django.urls import path

from .views import (
    ApprovalDecisionView,
    ApprovalListView,
    KillSwitchView,
    ToolInvocationListView,
    ToolPolicyDetailView,
    ToolPolicyListView,
)

urlpatterns = [
    path("policies/", ToolPolicyListView.as_view(), name="policy-list"),
    path("policies/<str:tool_name>/", ToolPolicyDetailView.as_view(), name="policy-detail"),
    path("killswitch/", KillSwitchView.as_view(), name="killswitch"),
    path("invocations/", ToolInvocationListView.as_view(), name="invocation-list"),
    path("approvals/", ApprovalListView.as_view(), name="approval-list"),
    path(
        "approvals/<int:pk>/<str:decision>/",
        ApprovalDecisionView.as_view(),
        name="approval-decision",
    ),
]
