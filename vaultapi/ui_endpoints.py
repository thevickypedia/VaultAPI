import base64
import logging
import os
import pathlib
import secrets
import sqlite3
import warnings
from http import HTTPStatus

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from . import api_endpoints, auth, database, exceptions, models

LOGGER = logging.getLogger("uvicorn.default")


async def index():
    """Endpoint for the UI of the API server.

    Returns:
        HTMLResponse:
        Returns the HTML content for the UI.
    """
    with open(pathlib.Path(__file__).parent / "index.html") as file:
        return HTMLResponse(content=file.read(), status_code=200)


async def ui_login(request: Request):
    """Validate credentials submitted by the login form.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        JSONResponse:
        Returns 200 on success, 401/403 on failure.
    """
    if request.client.host not in models.session.allowed_origins:
        return JSONResponse(
            status_code=HTTPStatus.FORBIDDEN.real,
            content={"detail": HTTPStatus.FORBIDDEN.phrase},
        )
    body = await request.json()
    apikey = str(body.get("apikey", ""))
    totp_code = str(body.get("totp_code", "")).strip()

    if apikey.startswith("\\"):
        apikey = bytes(apikey, "utf-8").decode(encoding="unicode_escape")

    if not secrets.compare_digest(apikey, models.env.apikey):
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid credentials"},
        )

    if models.env.totp_token:
        try:
            import pyotp

            if not pyotp.TOTP(models.env.totp_token).verify(totp_code):
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
        return JSONResponse(
            status_code=HTTPStatus.UNAUTHORIZED.real,
            content={"detail": "Invalid credentials"},
        )

    auth.UI_SESSION["token"] = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    return JSONResponse(content={"token": auth.UI_SESSION["token"]})


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
