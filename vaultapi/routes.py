from typing import List

from fastapi import Depends
from fastapi.routing import APIRoute

from . import api_endpoints, models, rate_limit, ui_endpoints

DEPENDENCIES = [
    Depends(dependency=rate_limit.RateLimiter(each_rate_limit).init)
    for each_rate_limit in models.env.rate_limit
]


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
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/login",
            endpoint=ui_endpoints.ui_login,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/logout",
            endpoint=ui_endpoints.ui_logout,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/tables",
            endpoint=ui_endpoints.ui_list_tables,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/table/{table_name}",
            endpoint=ui_endpoints.ui_get_table,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/table/{table_name}",
            endpoint=ui_endpoints.ui_create_table,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/table/{table_name}",
            endpoint=ui_endpoints.ui_delete_table,
            methods=["DELETE"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/secret",
            endpoint=ui_endpoints.ui_put_secret,
            methods=["PUT"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/secret",
            endpoint=ui_endpoints.ui_delete_secret,
            methods=["DELETE"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/ui/import",
            endpoint=ui_endpoints.ui_import_secrets,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
    ]


def api_routes() -> List[APIRoute]:
    """Get the API routes to be added for the server.

    Returns:
        List[APIRoute]:
        Returns the routes as a list of APIRoute objects.
    """
    return [
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
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/get-table",
            endpoint=api_endpoints.get_table,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/list-tables",
            endpoint=api_endpoints.list_tables,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/put-secret",
            endpoint=api_endpoints.put_secret,
            methods=["PUT"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/delete-secret",
            endpoint=api_endpoints.delete_secret,
            methods=["DELETE"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/create-table",
            endpoint=api_endpoints.create_table,
            methods=["POST"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path="/delete-table",
            endpoint=api_endpoints.delete_table,
            methods=["DELETE"],
            dependencies=DEPENDENCIES,
        ),
    ]
