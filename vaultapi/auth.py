import logging
import secrets
import time
import warnings
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database, exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()

UI_AUTHENTICATOR = "VaultAPI-UI"


async def ui_login(request: Request) -> bool:
    """Validate the login credentials from the request body.

    Args:
        request: Reference to the FastAPI request object (body must contain apikey, secret, totp_code).

    Returns:
        bool:
        ``True`` if all credentials are valid, ``False`` otherwise.
    """
    body = await request.json()
    apikey = str(body.get("apikey", ""))
    secret = str(body.get("secret", ""))
    totp_code = str(body.get("totp_code", "")).strip()

    if apikey.startswith("\\"):
        apikey = bytes(apikey, "utf-8").decode(encoding="unicode_escape")

    if secret.startswith("\\"):
        secret = bytes(secret, "utf-8").decode(encoding="unicode_escape")

    if not secrets.compare_digest(apikey, models.env.apikey):
        LOGGER.debug("Invalid api key received")
        return False

    if not secrets.compare_digest(secret, models.env.secret):
        LOGGER.debug("Invalid secret received")
        return False

    if models.env.totp_token:
        try:
            import pyotp

            if not pyotp.TOTP(models.env.totp_token).verify(totp_code):
                LOGGER.debug("Invalid totp token received")
                return False
        except Exception as error:
            LOGGER.error("TOTP validation error: %s", error)
            return False
    else:
        warnings.warn(
            "TOTP not enabled but UI login attempt has been made.", UserWarning
        )
        LOGGER.warning("TOTP not enabled but UI login attempt has been made.")
        return False

    return True


def blocked(host: str) -> None:
    """Raise a 403 APIResponse if the host is within an active cooloff window.

    Args:
        host: Hostname or IP address of the client.

    Raises:
        APIResponse:
        - 403: If the host has a non-expired ``blocked_until`` entry.
    """
    blocked_until = database.get_blocked_until(host)
    if blocked_until is not None:
        LOGGER.info(
            "Host: %s has been blocked after repeated failed auth attempts", host
        )
        raise exceptions.APIResponse(
            status_code=HTTPStatus.FORBIDDEN.real,
            detail=f"Blocked until {blocked_until}",
        )


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
    blocked(host)
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
