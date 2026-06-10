import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from . import api_endpoints, database, models, routes, version

VaultAPI = FastAPI(
    title="VaultAPI",
    description="Lightweight service to serve secrets and environment variables",
    version=version.__version__,
)
LOGGER = logging.getLogger("uvicorn.default")


def lifespan() -> None:
    """Enables CORS policy."""
    # Log the IP info
    LOGGER.info("Setting CORS policy")
    VaultAPI.add_middleware(
        CORSMiddleware,  # noqa: PyTypeChecker
        allow_origins=models.env.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            # Default headers
            "host",
            "user-agent",
            "authorization",
            "authenticator",
        ],
    )

    VaultAPI.routes.extend(routes.api_routes())
    if models.env.enable_ui:
        database.create_ui_session_table()
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


lifespan()
