from django.urls import path

from .views import (
    DeviceListView,
    EmployeeDetailView,
    EmployeeListView,
    PasswordResetRetrievalView,
)

urlpatterns = [
    path("employees/", EmployeeListView.as_view(), name="employee-list"),
    path("employees/<str:sam>/", EmployeeDetailView.as_view(), name="employee-detail"),
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path(
        "password-resets/<uuid:reference>/",
        PasswordResetRetrievalView.as_view(),
        name="password-reset-retrieve",
    ),
]
