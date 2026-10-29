from django.urls import path

from .views import (
    AcceptInviteView,
    DepartmentDetailView,
    DepartmentListCreateView,
    MemberDetailView,
    MemberListCreateView,
    MemberPasswordView,
    OrganizationDetailView,
)

urlpatterns = [
    path("", OrganizationDetailView.as_view(), name="organization-detail"),
    path("departments/", DepartmentListCreateView.as_view(), name="department-list"),
    path("departments/<int:pk>/", DepartmentDetailView.as_view(), name="department-detail"),
    path("members/", MemberListCreateView.as_view(), name="member-list"),
    path("members/<int:pk>/", MemberDetailView.as_view(), name="member-detail"),
    path("members/<int:pk>/password/", MemberPasswordView.as_view(), name="member-password"),
    path("invites/accept/", AcceptInviteView.as_view(), name="invite-accept"),
]
