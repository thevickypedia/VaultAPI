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
SWAGGER_JS = "<script>\n" + (pathlib.Path(__file__).parent / "templates" / "swagger.js").read_text() + "\n</script>"


async def get_swagger_html(app: FastAPI) -> HTMLResponse:
    """Custom docs endpoint for the Swagger UI.

    See Also:
        The Swagger UI is customized to scroll to the operation when a hyperlink from the description block is selected.

    Returns:
        HTMLResponse:
        Returns an HTMLResponse object with the customized UI.
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
    """Redirect to docs page.

    Returns:
        RedirectResponse:
        Redirects the user to ``/docs`` page.
    """
    return RedirectResponse(enums.APIRoutes.docs)


def docs_handler(api: FastAPI, func: Callable) -> None:
    """Removes the default Swagger UI endpoint and adds a custom ``docs`` endpoint.

    Args:
        api: FastAPI object to modify the routes.
        func: Callable function to be used as the endpoint for the custom docs.

    References:
        https://swagger.io/docs/open-source-tools/swagger-ui/usage/configuration/
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
    """Generates hyperlink for a particular API route to be included in the description.

    Args:
        route: APIRoute or APIWebSocketRoute object.

    Returns:
        str:
        Returns the hyperlink as a string.
    """
    method = list(route.methods)[0].lower()
    route_path = route.path.lstrip("/").replace("-", "_")
    return f"\n- <a href='#/default/{route.name}_{route_path}_{method}'>{route.path}</a><br>"


def get_desc(api_routes: List[APIRoute]) -> str:
    """Construct a detailed description for the API docs.

    Returns:
        str:
        Returns the description as a string.
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
    description += f"\n\n**UI Features:** {'Enabled' if models.env.enable_ui else 'Disabled'}"
    description += "\n\n#### Links"
    description += "\n- <a href='/playground'>Playground</a><br>"
    description += "\n- <a href='https://pypi.org/project/VaultAPI/'>PyPi</a><br>"
    description += "\n- <a href='https://github.com/thevickypedia/VaultAPI'>GitHub</a><br>"
    description += "\n- <a href='https://thevickypedia.github.io/VaultAPI/'>Runbook</a><br>"
    description += "<br><br>"
    return description
