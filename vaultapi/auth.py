import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from http import HTTPStatus

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import exceptions, models

LOGGER = logging.getLogger("uvicorn.default")
SECURITY = HTTPBearer()

UI_SESSION = {"authenticator": "VaultAPI-UI"}


def _signing_key() -> bytes:
    """Derive an HMAC signing key from the two configured secrets."""
    return hashlib.sha256((models.env.secret + models.env.apikey).encode()).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def create_ui_token(hostname: str, lifetime: int | None = None) -> str:
    """Issue a signed HS256 JWT bound to *hostname*.

    Args:
        hostname: The ``request.url.hostname`` value at login time — embedded as
                  the ``iss`` claim and verified on every subsequent request.
        lifetime: Token TTL in seconds; defaults to ``env.ui_lifetime``.

    Returns:
        str:
        A compact JWT string (``header.payload.signature``).
    """
    header = _b64url(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    now = int(time.time())
    ttl = lifetime if lifetime is not None else models.env.ui_lifetime
    payload = _b64url(
        json.dumps(
            {
                "sub": "vaultapi-ui",
                "iss": hostname,
                "iat": now,
                "exp": now + ttl,
                "jti": uuid.uuid4().hex,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    sig = _b64url(hmac.new(_signing_key(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_ui_token(token: str, hostname: str) -> bool:
    """Verify a UI JWT: signature integrity, expiry, and issuer binding.

    Args:
        token: The JWT string from the Authorization header.
        hostname: The ``request.url.hostname`` of the incoming request.

    Returns:
        bool:
        ``True`` only when signature, expiry, and ``iss`` all pass.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = _b64url(
            hmac.new(_signing_key(), signing_input, hashlib.sha256).digest()
        )
        if not secrets.compare_digest(sig_b64, expected_sig):
            return False
        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("sub") != "vaultapi-ui":
            return False
        if int(claims.get("exp", 0)) <= int(time.time()):
            return False
        if claims.get("iss") != hostname:
            return False
        return True
    except Exception:
        return False


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
        authenticated = verify_ui_token(auth, request.url.hostname)
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
