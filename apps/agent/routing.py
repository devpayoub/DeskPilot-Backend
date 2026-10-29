"""WebSocket routes."""
from django.urls import re_path

from .consumers import RunTraceConsumer

websocket_urlpatterns = [
    re_path(r"^ws/runs/(?P<run_id>\d+)/$", RunTraceConsumer.as_asgi()),
]
