from django.urls import path

from .views import (
    RunDetailView,
    RunListView,
    RunStepsView,
    RunWsTicketView,
    TicketDetailView,
    TicketListCreateView,
    TicketRunView,
)

urlpatterns = [
    path("tickets/", TicketListCreateView.as_view(), name="ticket-list"),
    path("tickets/<int:pk>/", TicketDetailView.as_view(), name="ticket-detail"),
    path("tickets/<int:pk>/run/", TicketRunView.as_view(), name="ticket-run"),
    path("runs/", RunListView.as_view(), name="run-list"),
    path("runs/<int:pk>/", RunDetailView.as_view(), name="run-detail"),
    path("runs/<int:pk>/steps/", RunStepsView.as_view(), name="run-steps"),
    path("runs/<int:pk>/ws-ticket/", RunWsTicketView.as_view(), name="run-ws-ticket"),
]
