import logging
import secrets
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()


async def validate(request: Request, apikey: HTTPAuthorizationCredentials) -> None:
    """Validates the auth request using HTTPBearer.

    Args:
        request: Takes the authorization header token as an argument.
        apikey: Basic APIKey required for all the routes.

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
    if apikey.credentials.startswith("\\"):
        auth = bytes(apikey.credentials, "utf-8").decode(encoding="unicode_escape")
    else:
        auth = apikey.credentials
    if secrets.compare_digest(auth, models.env.apikey):
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
