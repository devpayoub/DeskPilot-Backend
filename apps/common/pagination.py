from __future__ import annotations

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class DefaultPagination(PageNumberPagination):
    """Page-number pagination in the shape the web console expects.

    DRF's default envelope is ``{count, next, previous, results}``. The console's
    ``Paginated<T>`` also needs ``page`` and ``page_size`` to render a pager
    without re-deriving them from the URL, so they are added here rather than
    parsed client-side.
    """

    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response(
            {
                "count": self.page.paginator.count,
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "page": self.page.number,
                "page_size": self.get_page_size(self.request),
                "results": data,
            }
        )
