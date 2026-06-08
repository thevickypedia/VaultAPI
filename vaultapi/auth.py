import logging
import secrets
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()
UI_SESSION = {"token": ""}


async def validate(request: Request, authorization: HTTPAuthorizationCredentials) -> None:
    """Validates the auth request using HTTPBearer.

    Args:
        request: Takes the authorization header token as an argument.
        authorization: Basic APIKey required for API routes [OR] session token required for UI routes.

    Raises:
        APIResponse:
        - 401: If authorization is invalid.
        - 403: If host address is forbidden.
    """
    if request.client.host not in models.session.allowed_origins:
        LOGGER.info(
            "Host: %s has been blocked since it is not added to allowed list",
            request.client.host,
        )
        LOGGER.debug(models.session.allowed_origins)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.FORBIDDEN.real, detail=HTTPStatus.FORBIDDEN.phrase
        )
    if authorization.credentials.startswith("\\"):
        auth = bytes(authorization.credentials, "utf-8").decode(encoding="unicode_escape")
    else:
        auth = authorization.credentials
    authenticator = request.headers.get("authenticator")
    if authenticator == 'VaultAPI-UI':
        authenticated = UI_SESSION["token"] != "" and secrets.compare_digest(auth, UI_SESSION["token"])
    else:
        authenticated = secrets.compare_digest(auth, models.env.apikey)
    if authenticated:
        LOGGER.debug(
            "Connection received from client-host: %s, host-header: %s, x-fwd-host: %s",
            request.client.host,
            request.headers.get("host"),
            request.headers.get("x-forwarded-host"),
        )
        if user_agent := request.headers.get("user-agent"):
            LOGGER.debug("User agent: %s", user_agent)
        return
    raise exceptions.APIResponse(
        status_code=HTTPStatus.UNAUTHORIZED.real, detail=HTTPStatus.UNAUTHORIZED.phrase
    )
