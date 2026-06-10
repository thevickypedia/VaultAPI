import base64
import json
import logging
import os
import pathlib
import secrets
import sqlite3
import time
import warnings
from datetime import datetime
from http import HTTPStatus

import yaml
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates

from . import api_endpoints, auth, database, exceptions, models, version

LOGGER = logging.getLogger("uvicorn.default")
templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")


def blocked(request: Request) -> JSONResponse | None:
    """Function to check if the upstream server is blocked.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        JSONResponse:
        Returns a JSON response if the upstream server is allowed. Otherwise, returns None.
    """
    if request.url.hostname not in models.session.allowed_origins:
        LOGGER.info(
            "Host: %s has been blocked since it is not added to allowed list",
            request.url.hostname,
        )
        return JSONResponse(
            status_code=HTTPStatus.FORBIDDEN.real,
            content={"detail": HTTPStatus.FORBIDDEN.phrase},
        )
    return None


async def index(request: Request):
    """Endpoint for the UI of the API server.

    Returns:
        HTMLResponse:
        Returns the HTML content for the UI.
    """
    if response := blocked(request):
        return response
    return templates.TemplateResponse(
        name="index.html",
        request=request,
        context={
            "request": request,
            "authenticator": auth.UI_SESSION["authenticator"],
            "version": version.__version__,
        },
    )


async def ui_login(request: Request):
    """Validate credentials submitted by the login form.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        JSONResponse:
        Returns 200 on success, 401/403 on failure.
    """
    if response := blocked(request):
        return response
    body = await request.json()
    apikey = str(body.get("apikey", ""))
    totp_code = str(body.get("totp_code", "")).strip()

    if apikey.startswith("\\"):
        apikey = bytes(apikey, "utf-8").decode(encoding="unicode_escape")

    if not secrets.compare_digest(apikey, models.env.apikey):
        LOGGER.debug("Invalid api key received")
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid credentials"},
        )

    if models.env.totp_token:
        try:
            import pyotp

            if not pyotp.TOTP(models.env.totp_token).verify(totp_code):
                LOGGER.debug("Invalid totp token received")
                return JSONResponse(
                    status_code=HTTPStatus.UNAUTHORIZED.real,
                    content={"detail": "Invalid credentials"},
                )
        except Exception as error:
            LOGGER.error("TOTP validation error: %s", error)
            return JSONResponse(
                status_code=HTTPStatus.UNAUTHORIZED.real,
                content={"detail": "Invalid credentials"},
            )
    else:
        warnings.warn(
            "TOTP not enabled but UI login attempt has been made.", UserWarning
        )
        LOGGER.warning("TOTP not enabled but UI login attempt has been made.")
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid credentials"},
        )

    token = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    expires = int(time.time()) + models.env.ui_lifetime
    database.upsert_ui_session(
        token, request.url.hostname, expires, models.session.fernet
    )
    LOGGER.info(
        "Connection received from url-hostname: %s, host-header: %s, x-fwd-host: %s",
        request.url.hostname,
        request.headers.get("host"),
        request.headers.get("x-forwarded-host"),
    )
    LOGGER.info("UI login will expire at: %s", datetime.fromtimestamp(expires))
    return JSONResponse(content={"token": token, "expires": expires})


async def ui_logout(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Invalidate the active UI session server-side.

    Args:
        request: Reference to the FastAPI request object.
        session_token: Session token required to authenticate the logout request.

    Returns:
        JSONResponse:
        Returns 200 on success, 401/403 if the token is already invalid.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    database.delete_ui_session()
    LOGGER.info("UI session invalidated by logout request")
    return JSONResponse(content={"detail": "OK"})


async def ui_list_tables(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """List all tables for the UI.

    Args:
        request: Reference to the FastAPI request object.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response with the list of tables.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(content={"tables": database.list_tables()})


async def ui_get_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Get all secrets in a table, decrypted, for the UI.

    Args:
        request: Reference to the FastAPI request object.
        table_name: Name of the table to retrieve secrets from.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response with the decrypted key-value pairs.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    try:
        raw = await api_endpoints.retrieve_secrets(table_name)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    decrypted = {
        key: models.session.fernet.decrypt(value).decode("UTF-8")
        for key, value in raw.items()
    }
    return JSONResponse(content={"secrets": decrypted})


async def ui_create_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Create a new table for the UI.

    Args:
        request: Reference to the FastAPI request object.
        table_name: Name of the table to create.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response indicating success or failure.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    try:
        database.create_table(table_name, ["key", "value"])
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]}
        )
    return JSONResponse(content={"detail": "OK"})


async def ui_delete_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Delete a table for the UI.

    Args:
        request: Reference to the FastAPI request object.
        table_name: Name of the table to delete.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response indicating success or failure.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    body = await request.json()
    totp_code = str(body.get("totp_code", "")).strip()
    try:
        import pyotp

        if not pyotp.TOTP(models.env.totp_token).verify(totp_code):
            return JSONResponse(
                status_code=HTTPStatus.UNAUTHORIZED.real,
                content={"detail": "Invalid authenticator code"},
            )
    except Exception as error:
        LOGGER.error("TOTP validation error: %s", error)
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid authenticator code"},
        )
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    try:
        database.drop_table(table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]}
        )
    return JSONResponse(content={"detail": "OK"})


async def ui_put_secret(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Add or update a secret for the UI.

    Args:
        request: Reference to the FastAPI request object.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response indicating success or failure.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    body = await request.json()
    table_name = body.get("table_name", "default")
    key = body.get("key", "").strip()
    value = body.get("value", "")
    if not key:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": "Key cannot be empty"},
        )
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    encrypted = models.session.fernet.encrypt(value.encode("UTF-8"))
    database.put_secret(key=key, value=encrypted, table_name=table_name)
    return JSONResponse(content={"detail": "OK"})


async def ui_import_secrets(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Import multiple secrets into a table from a JSON, YAML, or .env payload.

    Args:
        request: Reference to the FastAPI request object.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response with counts of imported and skipped secrets.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    body = await request.json()
    table_name = body.get("table_name", "default")
    payload = body.get("payload", "")
    payload_type = body.get("payload_type", "").lower()

    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )

    try:
        if payload_type == "json":
            parsed = json.loads(payload)
            if not isinstance(parsed, dict):
                return JSONResponse(
                    status_code=HTTPStatus.BAD_REQUEST.real,
                    content={"detail": "JSON payload must be a flat object"},
                )
            pairs = {str(k): str(v) for k, v in parsed.items()}
        elif payload_type == "yaml":
            parsed = yaml.safe_load(payload)
            if not isinstance(parsed, dict):
                return JSONResponse(
                    status_code=HTTPStatus.BAD_REQUEST.real,
                    content={"detail": "YAML payload must be a flat mapping"},
                )
            pairs = {str(k): str(v) for k, v in parsed.items()}
        elif payload_type == "env":
            pairs = {}
            for line in payload.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    pairs[key] = value
        else:
            return JSONResponse(
                status_code=HTTPStatus.BAD_REQUEST.real,
                content={
                    "detail": f"Unsupported payload_type {payload_type!r}; use json, yaml, or env"
                },
            )
    except Exception as error:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": f"Failed to parse payload: {error}"},
        )

    if not pairs:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": "No key-value pairs found in payload"},
        )

    imported, skipped = 0, 0
    for key, value in pairs.items():
        if not key:
            skipped += 1
            continue
        try:
            encrypted = models.session.fernet.encrypt(value.encode("UTF-8"))
            database.put_secret(key=key, value=encrypted, table_name=table_name)
            imported += 1
        except Exception as error:
            LOGGER.error("Failed to import secret %r: %s", key, error)
            skipped += 1

    return JSONResponse(content={"imported": imported, "skipped": skipped})


async def ui_delete_secret(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Delete a secret for the UI.

    Args:
        request: Reference to the FastAPI request object.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response indicating success or failure.
    """
    try:
        await auth.validate(request, session_token)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    body = await request.json()
    totp_code = str(body.get("totp_code", "")).strip()
    try:
        import pyotp

        if not pyotp.TOTP(models.env.totp_token).verify(totp_code):
            return JSONResponse(
                status_code=HTTPStatus.UNAUTHORIZED.real,
                content={"detail": "Invalid authenticator code"},
            )
    except Exception as error:
        LOGGER.error("TOTP validation error: %s", error)
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid authenticator code"},
        )
    table_name = body.get("table_name", "default")
    key = body.get("key", "").strip()
    if not key:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": "Key cannot be empty"},
        )
    try:
        existing = await api_endpoints.retrieve_secret(key, table_name)
    except exceptions.APIResponse as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if not existing:
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Secret {key!r} not found"},
        )
    try:
        database.remove_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]}
        )
    return JSONResponse(content={"detail": "OK"})
