"""Short-lived, single-run tokens for the trace WebSocket.

A browser cannot set headers on a WebSocket handshake, so the token has to ride
in the query string — where it ends up in proxy logs, browser history and crash
reports. Putting the *session* access token there is indefensible: it is
long-lived and valid against the entire API.

So the console asks for a purpose-built one instead: 60 seconds, read-only, and
bound to exactly one run. Leaking it costs an attacker a minute of one ticket's
trace, not the account.
"""
from __future__ import annotations

from datetime import timedelta

from rest_framework_simplejwt.tokens import AccessToken

WS_TRACE_SCOPE = "ws:trace"
WS_TICKET_LIFETIME_SECONDS = 60


def mint_trace_ticket(user, run_id: int) -> str:
    """A token that can do exactly one thing: subscribe to this run's trace."""
    token = AccessToken.for_user(user)
    token.set_exp(lifetime=timedelta(seconds=WS_TICKET_LIFETIME_SECONDS))
    token["scope"] = WS_TRACE_SCOPE
    token["run"] = run_id
    return str(token)


def verify_trace_ticket(raw: str | None, run_id: int) -> AccessToken:
    """Raise ValueError unless the token is a live trace ticket for this run.

    The run check is the part that matters: without it, any authenticated user
    could subscribe to any other ticket's trace and read its tool output.
    """
    if not raw:
        raise ValueError("missing token")

    token = AccessToken(raw)

    if token.get("scope") != WS_TRACE_SCOPE:
        raise ValueError("not a trace ticket")
    if str(token.get("run")) != str(run_id):
        raise ValueError("ticket is for a different run")

    return token
