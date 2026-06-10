import logging
import secrets
import time
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database, exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()

UI_SESSION = {"authenticator": "VaultAPI-UI"}


async def validate(
    request: Request, authorization: HTTPAuthorizationCredentials
) -> None:
    """Validates the auth request using HTTPBearer.

    Args:
        request: Takes the authorization header token as an argument.
        authorization: Basic APIKey required for API routes [OR] session token required for UI routes.

    Raises:
        APIResponse:
        - 401: If authorization is invalid.
        - 403: If host address is forbidden.
    """
    if request.url.hostname not in models.session.allowed_origins:
        LOGGER.info(
            "Host: %s has been blocked since it is not added to allowed list",
            request.url.hostname,
        )
        LOGGER.debug(models.session.allowed_origins)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.FORBIDDEN.real, detail=HTTPStatus.FORBIDDEN.phrase
        )
    if authorization.credentials.startswith("\\"):
        auth = bytes(authorization.credentials, "utf-8").decode(
            encoding="unicode_escape"
        )
    else:
        auth = authorization.credentials
    if request.headers.get("authenticator", "") == UI_SESSION["authenticator"]:
        LOGGER.debug("Assuming UI authenticator")
        session = database.get_ui_session(models.session.fernet)
        authenticated = bool(
            session
            and secrets.compare_digest(auth, session["token"])
            and session["host"] == request.url.hostname
            and int(session["exp"]) > int(time.time())
        )
    else:
        LOGGER.debug("Assuming API authenticator")
        authenticated = secrets.compare_digest(auth, models.env.apikey)
    if authenticated:
        LOGGER.debug(
            "Connection received from url-hostname: %s, host-header: %s, x-fwd-host: %s",
            request.url.hostname,
            request.headers.get("host"),
            request.headers.get("x-forwarded-host"),
        )
        if user_agent := request.headers.get("user-agent"):
            LOGGER.debug("User agent: %s", user_agent)
        return
    LOGGER.debug("Invalid apikey [OR] session token")
    raise exceptions.APIResponse(
        status_code=HTTPStatus.UNAUTHORIZED.real, detail=HTTPStatus.UNAUTHORIZED.phrase
    )
