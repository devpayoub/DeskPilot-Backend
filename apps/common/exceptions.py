from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger(__name__)


def api_exception_handler(exc, context):
    """Normalise every DRF error into {"error": {"code", "message", "details"}}.

    Keeps the frontend from having to branch on DRF's two different error shapes
    (field-error dicts vs. detail strings).
    """
    response = drf_exception_handler(exc, context)
    if response is None:
        # Unhandled exception: let Django's 500 path log it, but keep a clean body.
        logger.exception("unhandled API exception", exc_info=exc)
        return Response(
            {"error": {"code": "internal_error", "message": "An unexpected error occurred."}},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    detail = response.data
    if isinstance(detail, dict) and "detail" in detail and len(detail) == 1:
        message = str(detail["detail"])
        details = {}
    elif isinstance(detail, dict):
        message = "Validation failed."
        details = detail
    else:
        message = str(detail)
        details = {}

    response.data = {
        "error": {
            "code": getattr(exc, "default_code", "error"),
            "message": message,
            "details": details,
        }
    }
    return response
