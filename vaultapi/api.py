import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from . import api_endpoints, database, models, routes, version


async def delete_ui_session(event: str) -> None:
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
    description="Lightweight service to serve secrets and environment variables",
    version=version.__version__,
    lifespan=lifespan,
)
LOGGER = logging.getLogger("uvicorn.default")


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

    VaultAPI.routes.extend(routes.api_routes())
    if models.env.enable_ui:
        database.create_auth_tables()
        VaultAPI.routes.extend(routes.ui_routes())
    else:  # pragma: no cover
        VaultAPI.routes.append(
            APIRoute(
                path="/",
                endpoint=api_endpoints.docs,
                methods=["GET"],
                include_in_schema=False,
            )
        )


startup()
