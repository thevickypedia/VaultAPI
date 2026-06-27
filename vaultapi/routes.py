"""Routes module that constructs and returns the FastAPI ``APIRoute`` lists for API and UI endpoints."""

from typing import List

from fastapi import Depends
from fastapi.routing import APIRoute

from . import api_endpoints, enums, models, rate_limit, ui_endpoints

DEPENDENCIES = [
    Depends(dependency=rate_limit.RateLimiter(each_rate_limit).init) for each_rate_limit in models.env.rate_limit
]


def ui_routes() -> List[APIRoute]:
    """Build the list of UI routes for the FastAPI application.

    Returns:
        List[APIRoute]:
        All UI ``APIRoute`` objects to be registered on the application.
    """
    return [
        APIRoute(
            path=enums.UIRoutes.root,
            endpoint=ui_endpoints.index,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.playground,
            endpoint=ui_endpoints.playground,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_login,
            endpoint=ui_endpoints.ui_login,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_logout,
            endpoint=ui_endpoints.ui_logout,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_tables,
            endpoint=ui_endpoints.ui_list_tables,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_table,
            endpoint=ui_endpoints.ui_get_table,
            methods=["GET"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_table,
            endpoint=ui_endpoints.ui_create_table,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_table,
            endpoint=ui_endpoints.ui_rename_table,
            methods=["PATCH"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_table,
            endpoint=ui_endpoints.ui_delete_table,
            methods=["DELETE"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_secret,
            endpoint=ui_endpoints.ui_put_secret,
            methods=["PUT"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_secret,
            endpoint=ui_endpoints.ui_delete_secret,
            methods=["DELETE"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.UIRoutes.ui_import,
            endpoint=ui_endpoints.ui_import_secrets,
            methods=["POST"],
            include_in_schema=False,
            dependencies=DEPENDENCIES,
        ),
    ]


def api_routes() -> List[APIRoute]:
    """Build the list of API routes for the FastAPI application.

    Returns:
        List[APIRoute]:
        All API ``APIRoute`` objects to be registered on the application.
    """
    return [
        # Base routes (no auth)
        APIRoute(
            path=enums.APIRoutes.health,
            endpoint=api_endpoints.health,
            methods=["GET"],
            include_in_schema=False,
        ),
        APIRoute(
            path=enums.APIRoutes.version,
            endpoint=api_endpoints.get_version,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        # Basic authentication (GET [OR] POST)
        APIRoute(
            path=enums.APIRoutes.get_secret,
            endpoint=api_endpoints.get_secret,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.get_table,
            endpoint=api_endpoints.get_table,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.list_tables,
            endpoint=api_endpoints.list_tables,
            methods=["GET"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.create_table,
            endpoint=api_endpoints.create_table,
            methods=["POST"],
            dependencies=DEPENDENCIES,
        ),
        # Advanced routes (PUT [OR] PATCH [OR] DELETE)
        APIRoute(
            path=enums.APIRoutes.put_secret,
            endpoint=api_endpoints.put_secret,
            methods=["PUT"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.delete_secret,
            endpoint=api_endpoints.delete_secret,
            methods=["DELETE"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.rename_table,
            endpoint=api_endpoints.rename_table,
            methods=["PATCH"],
            dependencies=DEPENDENCIES,
        ),
        APIRoute(
            path=enums.APIRoutes.delete_table,
            endpoint=api_endpoints.delete_table,
            methods=["DELETE"],
            dependencies=DEPENDENCIES,
        ),
    ]
