import logging
from multiprocessing.process import current_process

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models, routes, version

VaultAPI = FastAPI(
    title="VaultAPI",
    description="Lightweight service to serve secrets and environment variables",
    version=version.__version__,
)


def enable_cors() -> None:
    """Enables CORS policy."""
    origins = [
        "http://localhost.com",
        "https://localhost.com",
    ]
    for website in models.env.allowed_origins:
        origins.append(f"http://{website.host}")  # noqa: HttpUrlsUsage
        origins.append(f"https://{website.host}")
    # Log the IP info
    if current_process().name in ("SpawnProcess-1", "MainProcess"):
        logger = logging.getLogger("uvicorn.default")
        logger.info("Setting CORS policy")
        logger.info("Allowed default origins: %s", ", ".join(models.DEFAULT_ALLOWED))
        if models.env.allowed_origins:
            logger.info(
                "Allowed origins: %s",
                ", ".join(str(url) for url in models.env.allowed_origins),
            )
        if models.env.allowed_ip_range:
            logger.info("Allowed IP range: %s", ", ".join(models.env.allowed_ip_range))
        logger.debug("Overall allowed origins: %s", models.session.allowed_origins)
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


enable_cors()
VaultAPI.routes.extend(routes.get_all_routes())
