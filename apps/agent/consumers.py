"""WebSocket consumer for the live agent trace.

Authentication is not optional here: a trace contains the ticket body and tool
output, so an unauthenticated socket would leak customer data. The token rides in
the query string because browsers cannot set headers on a WebSocket handshake —
which is exactly why it must be a short-lived, single-run ticket rather than a
session access token. See ``ws_tokens.py``.
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .ws_tokens import verify_trace_ticket

logger = logging.getLogger(__name__)


class RunTraceConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.run_id = self.scope["url_route"]["kwargs"]["run_id"]
        self.group_name = f"run.{self.run_id}"

        token = parse_qs(self.scope.get("query_string", b"").decode()).get("token", [None])[0]
        try:
            verify_trace_ticket(token, self.run_id)
        except Exception as exc:
            # 4401 unauthenticated, 4403 forbidden: a valid token for someone
            # else's run is the second case, not the first.
            logger.info("rejected trace socket for run=%s: %s", self.run_id, exc)
            await self.close(code=4403 if token else 4401)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self.send_json({"type": "connected", "run_id": self.run_id})

    async def disconnect(self, code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def run_step(self, event):
        await self.send_json(event["payload"])

    async def receive_json(self, content, **kwargs):
        """The trace is server-push only; a client message is a no-op."""
        return None
