import logging
import secrets
import time
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database, exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()

UI_AUTHENTICATOR = "VaultAPI-UI"


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
        - 403: If host address is forbidden (blocked after repeated failures).
    """
    host = request.client.host
    blocked_until = database.get_blocked_until(host)
    if blocked_until is not None:
        LOGGER.info(
            "Host: %s has been blocked after repeated failed auth attempts", host
        )
        raise exceptions.APIResponse(
            status_code=HTTPStatus.FORBIDDEN.real,
            detail=f"Blocked until {blocked_until}",
        )
    if authorization.credentials.startswith("\\"):
        auth = bytes(authorization.credentials, "utf-8").decode(
            encoding="unicode_escape"
        )
    else:
        auth = authorization.credentials
    if request.headers.get("authenticator", "") == UI_AUTHENTICATOR:
        LOGGER.debug("Assuming UI authenticator")
        session = database.get_ui_session(models.session.fernet)
        authenticated = bool(
            session
            and secrets.compare_digest(auth, session["token"])
            and session["host"] == host
            and int(session["exp"]) > int(time.time())
        )
    else:
        LOGGER.debug("Assuming API authenticator")
        authenticated = secrets.compare_digest(auth, models.env.apikey)
    if authenticated:
        LOGGER.debug(
            "Connection received from host: %s, host-header: %s, x-fwd-host: %s",
            host,
            request.headers.get("host"),
            request.headers.get("x-forwarded-host"),
        )
        if user_agent := request.headers.get("user-agent"):
            LOGGER.debug("User agent: %s", user_agent)
        database.reset_failed_auth(host)
        return
    LOGGER.debug("Invalid apikey [OR] session token")
    database.increment_failed_auth(host)
    raise exceptions.APIResponse(
        status_code=HTTPStatus.UNAUTHORIZED.real, detail=HTTPStatus.UNAUTHORIZED.phrase
    )
