import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from . import api_endpoints, models, routes, version

VaultAPI = FastAPI(
    title="VaultAPI",
    description="Lightweight service to serve secrets and environment variables",
    version=version.__version__,
)
LOGGER = logging.getLogger("uvicorn.default")


def lifespan() -> None:
    """Enables CORS policy."""
    origins = [
        "http://localhost.com",
        "https://localhost.com",
    ]
    for website in models.env.allowed_origins:
        origins.append(f"http://{website.host}")  # noqa: HttpUrlsUsage
        origins.append(f"https://{website.host}")

    # Log the IP info
    LOGGER.info("Setting CORS policy")
    LOGGER.info("Allowed default origins: %s", ", ".join(models.DEFAULT_ALLOWED))
    if models.env.allowed_origins:
        LOGGER.info(
            "Allowed origins: %s",
            ", ".join(str(url) for url in models.env.allowed_origins),
        )
    if models.env.allowed_ip_range:
        LOGGER.info("Allowed IP range: %s", ", ".join(models.env.allowed_ip_range))
    LOGGER.debug("Overall allowed origins: %s", models.session.allowed_origins)

    VaultAPI.add_middleware(
        CORSMiddleware,  # noqa: PyTypeChecker
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            # Default headers
            "host",
            "user-agent",
            "authorization",
        ],
    )

    VaultAPI.routes.extend(routes.api_routes())
    if models.env.enable_ui:
        VaultAPI.routes.extend(routes.ui_routes())
    else:
        VaultAPI.routes.append(
            APIRoute(
                path="/",
                endpoint=api_endpoints.docs,
                methods=["GET"],
                include_in_schema=False,
            )
        )


lifespan()
