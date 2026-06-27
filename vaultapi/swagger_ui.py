"""Swagger UI module that customizes the docs endpoint and generates the API description."""

import logging
import pathlib
import sys
from typing import Callable, List

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.routing import APIRoute

from . import enums, models

LOGGER = logging.getLogger("uvicorn.default")
SWAGGER_JS = "<script>\n" + (pathlib.Path(__file__).parent / "templates" / "swagger_ui.js").read_text() + "\n</script>"


async def get_swagger_html(app: FastAPI) -> HTMLResponse:
    """Render the customized Swagger UI HTML page.

    See Also:
        Injects a custom JavaScript snippet (``swagger_ui.js``) before ``</body>``
        to enable smooth scrolling to an operation when a hyperlink from the
        description block is clicked.

    Args:
        app: FastAPI application instance used to extract the title and OpenAPI URL.

    Returns:
        HTMLResponse:
        HTML page with the customized Swagger UI and injected JavaScript.
    """
    html_content = get_swagger_ui_html(
        title=app.__dict__.get("title", app.__name__),
        openapi_url=app.__dict__.get("openapi_url", "/openapi.json"),
        swagger_ui_parameters={
            "deepLinking": True,
            "persistAuthorization": False,
            "displayRequestDuration": True,
            "docExpansion": "list",
        },
    )
    new_content = html_content.body.decode().replace("</body>", SWAGGER_JS + "</body>")
    return HTMLResponse(new_content)


async def docs_redirect() -> RedirectResponse:
    """Redirect the root path to the ``/docs`` page.

    Returns:
        RedirectResponse:
        302 redirect to ``/docs``.
    """
    return RedirectResponse(enums.APIRoutes.docs)


def docs_handler(api: FastAPI, func: Callable) -> None:
    """Replace the default Swagger UI route with the custom docs endpoint.

    Args:
        api: FastAPI application instance whose route list is modified in-place.
        func: Callable to register as the new ``/docs`` endpoint handler.
    """
    for __route in api.routes:
        if __route.__dict__.get("name", "") == "swagger_ui_html":
            api.routes.remove(__route)
    api.routes.append(
        APIRoute(
            path=enums.APIRoutes.docs,
            endpoint=func,
            methods=["GET"],
            include_in_schema=False,
        ),
    )


def generate_hyperlink(route: APIRoute) -> str:
    """Generate a Swagger UI deep-link anchor tag for an API route.

    Args:
        route: The ``APIRoute`` object to generate the hyperlink for.

    Returns:
        str:
        HTML anchor tag string pointing to the route's Swagger UI operation.
    """
    method = list(route.methods)[0].lower()
    route_path = route.path.lstrip("/").replace("-", "_")
    return f"\n- <a href='#/default/{route.name}_{route_path}_{method}'>{route.path}</a><br>"


def get_desc(api_routes: List[APIRoute]) -> str:
    """Build the full API description string for the Swagger UI overview.

    Args:
        api_routes: List of registered API routes used to generate the feature links.

    Returns:
        str:
        Markdown/HTML description string assigned to the FastAPI application.
    """
    description = "**Lightweight API to store/retrieve secrets to/from an encrypted Database 🔐**"
    description += (
        "\n\nVaultAPI provides cutting-edge security features like AES-GCM, Fernet encryption, "
        "and rate limiting all out of the box. It also includes transit encryption to ensure that the secrets are "
        "encrypted during transit to protect against man-in-the-middle attacks."
    )
    description += f"\n\n**Python version:** {sys.version.split()[0]}"
    description += "\n\n#### Basic Features"
    for route in api_routes:
        if route.include_in_schema:
            description += generate_hyperlink(route)
    description += f"\n\n**UI Features:** {'✅' if models.env.enable_ui else '❌'}"
    description += "\n\n#### Links"
    description += "\n- <a href='/playground'>Playground</a><br>"
    description += "\n- <a href='https://pypi.org/project/VaultAPI/'>PyPi</a><br>"
    description += "\n- <a href='https://github.com/thevickypedia/VaultAPI'>GitHub</a><br>"
    description += "\n- <a href='https://thevickypedia.github.io/VaultAPI/'>Runbook</a><br>"
    description += "<br><br>"
    return description
