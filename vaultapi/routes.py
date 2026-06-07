from typing import List

from fastapi import Depends
from fastapi.routing import APIRoute

from . import api_endpoints, models, rate_limit, ui_endpoints


def ui_routes() -> List[APIRoute]:
    """Get the UI routes to be added for the API server.

    Returns:
        List[APIRoute]:
        Returns the UI routes as a list of APIRoute objects.
    """
    return [
        APIRoute(
            path="/",
            endpoint=ui_endpoints.index,
            methods=["GET"],
            include_in_schema=False,
        )
    ]


def get_all_routes() -> List[APIRoute]:
    """Get all the routes to be added for the API server.

    Returns:
        List[APIRoute]:
        Returns the routes as a list of APIRoute objects.
    """
    dependencies = [
        Depends(dependency=rate_limit.RateLimiter(each_rate_limit).init)
        for each_rate_limit in models.env.rate_limit
    ]
    routes = [
        APIRoute(
            path="/health",
            endpoint=api_endpoints.health,
            methods=["GET"],
            include_in_schema=False,
        ),
        APIRoute(
            path="/get-secret",
            endpoint=api_endpoints.get_secret,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/get-table",
            endpoint=api_endpoints.get_table,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/list-tables",
            endpoint=api_endpoints.list_tables,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/put-secret",
            endpoint=api_endpoints.put_secret,
            methods=["PUT"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/delete-secret",
            endpoint=api_endpoints.delete_secret,
            methods=["DELETE"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/create-table",
            endpoint=api_endpoints.create_table,
            methods=["POST"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/delete-table",
            endpoint=api_endpoints.delete_table,
            methods=["DELETE"],
            dependencies=dependencies,
        ),
    ]
    return routes
