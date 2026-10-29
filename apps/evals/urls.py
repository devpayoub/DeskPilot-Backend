from django.urls import path

from .views import EvalRunListView

urlpatterns = [
    path("runs/", EvalRunListView.as_view(), name="eval-run-list"),
]
