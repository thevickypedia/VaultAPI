import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute

from . import database, enums, models, routes, swagger_ui, version


async def delete_ui_session(event: str) -> None:
    """Clear any existing UI sessions, so the tokens can't be re-used when the server is restarted."""
    if database.get_ui_session(models.session.fernet):
        LOGGER.info("Existing UI session found during %s, removing it.", event)
        database.delete_ui_session()
    else:
        LOGGER.info("No UI session found during %s.", event)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Lifespan context manager."""
    asyncio.create_task(delete_ui_session("startup"))
    yield
    asyncio.create_task(delete_ui_session("shutdown"))


VaultAPI = FastAPI(
    title="VaultAPI",
    version=version.__version__,
    lifespan=lifespan,
)
VaultAPI.__name__ = ("VaultAPI",)
LOGGER = logging.getLogger("uvicorn.default")


async def docs() -> HTMLResponse:
    """Returns the docs page as an HTMLResponse object."""
    return await swagger_ui.get_swagger_html(VaultAPI)


def startup() -> None:
    """Enables CORS policy and API and UI routes."""
    # Log the IP info
    LOGGER.info("Setting CORS policy")
    VaultAPI.add_middleware(
        CORSMiddleware,  # noqa: PyTypeChecker
        allow_origins=models.env.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            # Custom headers
            "mfa-code",
        ],
    )

    # Register docs endpoint to handle SwaggerUI
    swagger_ui.docs_handler(api=VaultAPI, func=docs)
    VaultAPI.routes.append(
        APIRoute(
            path=enums.APIRoutes.docs,
            endpoint=docs,
            methods=["GET"],
            include_in_schema=False,
        )
    )

    api_routes = routes.api_routes()
    description = swagger_ui.get_desc(api_routes)
    VaultAPI.description = description

    VaultAPI.routes.extend(api_routes)
    if models.env.enable_ui:
        database.create_auth_tables()
        ui_routes = routes.ui_routes()
        VaultAPI.routes.extend(ui_routes)
    else:  # pragma: no cover
        # Redirect root page to `/docs` if the UI is disabled
        VaultAPI.routes.append(
            APIRoute(
                path="/",
                endpoint=swagger_ui.docs_redirect,
                methods=["GET"],
                include_in_schema=False,
            )
        )


startup()
