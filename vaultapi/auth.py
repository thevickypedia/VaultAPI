import logging
import secrets
import time
from enum import Enum
from http import HTTPStatus
from typing import NoReturn

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database, exceptions, header, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer(description="Use [Playground](/playground) to generate the authorization header")

UI_BASIC = lambda session, auth, host: bool(  # noqa: E731
    session
    and secrets.compare_digest(auth, session["token"])
    and session["host"] == host
    and int(session["exp"]) > int(time.time())
)
API_BASIC = lambda auth: header.validate(auth, models.env.apikey, models.env.authorization_validity)  # noqa: E731
API_ADVANCED = lambda auth: header.validate(  # noqa: E731
    auth, f"{models.env.apikey}.{models.env.secret}", models.env.authorization_validity
)


class AuthType(Enum):
    """Model for the authentication type.

    >>> AuthType

    """

    ui_basic = "UI_BASIC"
    ui_login = "UI_LOGIN"
    ui_advanced = "UI_ADVANCED"

    api_basic = "API_BASIC"
    api_advanced = "API_ADVANCED"


def unauthorized(host: str) -> NoReturn:
    """Raise a 403 APIResponse if the host is unauthorized."""
    database.increment_failed_auth(host)
    raise exceptions.APIResponse(status_code=HTTPStatus.UNAUTHORIZED.real, detail=HTTPStatus.UNAUTHORIZED.phrase)


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


async def validate_totp(totp_code: str) -> bool | NoReturn:
    """Validate the login credentials from the request body.

    Args:
        totp_code: TOTP code received from the client.

    Returns:
        bool:
        ``True`` if totp code is valid, ``False`` otherwise.
    """
    try:
        import pyotp

        if models.env.totp_token and pyotp.TOTP(models.env.totp_token).verify(totp_code):
            return True
        else:
            LOGGER.warning(
                "TOTP verification failed, server-missing: %s, client-missing: %s",
                models.env.totp_token is None,
                totp_code is None,
            )
    except Exception as error:
        LOGGER.error("TOTP validation error: %s", error)
    return False


async def validate(
    request: Request, authorization: HTTPAuthorizationCredentials, auth_type: AuthType
) -> None | NoReturn:
    """Validates the auth request using HTTPBearer.

    Args:
        request: Takes the authorization header token as an argument.
        authorization: Basic APIKey required for API routes [OR] session token required for UI routes.
        auth_type: The type of authentication to use.

    Raises:
        APIResponse:
        - 401: If authorization is invalid.
        - 403: If host address is forbidden (blocked after repeated failures).
    """
    host = request.client.host
    await blocked(host)
    match auth_type:
        case AuthType.ui_login:
            # UI login page requires an API key and MFA code
            totp_code = request.headers.get("mfa-code", "")
            authenticated = API_BASIC(authorization.credentials) and await validate_totp(totp_code)
        case AuthType.ui_basic:
            # UI requests with read-only operations require a session token for validation
            session = database.get_ui_session(models.session.fernet)
            authenticated = UI_BASIC(session, authorization.credentials, host)
        case AuthType.ui_advanced:
            # UI requests with write/modify operations require a session token and MFA code for validation
            session = database.get_ui_session(models.session.fernet)
            totp_code = request.headers.get("mfa-code", "")
            authenticated = UI_BASIC(session, authorization.credentials, host) and await validate_totp(totp_code)
        case AuthType.api_basic:
            # API requests with read-only operations requires apikey + time based signature authentication
            authenticated = API_BASIC(authorization.credentials)
        case AuthType.api_advanced:
            # API requests with write/modify operations require apikey + secret + time based signature authentication
            authenticated = API_ADVANCED(authorization.credentials)
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
    unauthorized(host)
