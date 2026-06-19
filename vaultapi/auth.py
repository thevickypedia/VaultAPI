import logging
import secrets
import time
from http import HTTPStatus
from typing import NoReturn

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database, exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()

UI_AUTHENTICATOR = "VaultAPI-UI"


def unauthorized(host: str) -> NoReturn:
    """Raise a 403 APIResponse if the host is unauthorized."""
    database.increment_failed_auth(host)
    raise exceptions.APIResponse(
        status_code=HTTPStatus.UNAUTHORIZED.real, detail=HTTPStatus.UNAUTHORIZED.phrase
    )


async def blocked(host: str) -> None | NoReturn:
    """Raise a 403 APIResponse if the host is within an active cool-off window.

    Args:
        host: Hostname or IP address of the client.

    Raises:
        APIResponse:
        - 403: If the host has a non-expired ``blocked_until`` entry.
    """
    if auth_counter := database.get_blocked_until(host):
        LOGGER.info(
            "Host: %s has been blocked after %d failed auth attempts",
            host,
            auth_counter.count,
        )
        raise exceptions.APIResponse(
            status_code=HTTPStatus.FORBIDDEN.real,
            detail=f"Blocked until [{auth_counter.blocked_until}] after {auth_counter.count} failed auth attempts.",
        )


async def validate_totp(totp_code: str, host: str) -> bool | NoReturn:
    """Validate the login credentials from the request body.

    Args:
        totp_code: TOTP code received from the client.
        host: Hostname or IP address of the client.

    Returns:
        bool:
        ``True`` if totp code is valid, ``False`` otherwise.
    """
    try:
        import pyotp

        if models.env.totp_token and pyotp.TOTP(models.env.totp_token).verify(totp_code):
            return True
        else:
            LOGGER.warning("TOTP verification failed, missing: %s", models.env.totp_token is None)
    except Exception as error:
        LOGGER.error("TOTP validation error: %s", error)
    unauthorized(host)


async def validate(
    request: Request, authorization: HTTPAuthorizationCredentials
) -> None | NoReturn:
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
    await blocked(host)
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
    unauthorized(host)
