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

    VaultAPI.routes.extend(routes.get_all_routes())
    if models.env.enable_ui:
        assert all(
            (models.env.username, models.env.password, models.env.totp_token)
        ), "Username, password and TOTP token must be provided to enable UI"
        try:
            import uiauth
        except (ModuleNotFoundError, ImportError) as error:
            raise ImportError(
                "UI dependencies not found. Please install 'vaultapi[ui]' to enable UI features."
            ) from error
        # TODO: Revert this
        # models.complexity_checker(models.env.password, max_len=8)
        models.validate_totp_secret(models.env.totp_token)
        uiauth.protect(
            app=VaultAPI,
            username=models.env.username,
            password=models.env.password,
            totp_token=models.env.totp_token,
            session_timeout=models.env.ui_timeout,
            custom_logger=LOGGER,
            routes=routes.ui_routes(),
        )
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
