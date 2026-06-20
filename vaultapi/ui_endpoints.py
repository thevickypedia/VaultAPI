import base64
import json
import logging
import os
import pathlib
import sqlite3
import time
from datetime import datetime
from http import HTTPStatus

import yaml
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates

from . import api_endpoints, auth, database, models, version

LOGGER = logging.getLogger("uvicorn.default")
templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")


async def index(request: Request):
    """Endpoint for the UI of the API server.

    Returns:
        HTMLResponse:
        Returns the HTML content for the UI.
    """
    # Manually check for blocked since no auth is required for this endpoint
    await auth.blocked(request.client.host)
    return templates.TemplateResponse(
        name="index.html",
        request=request,
        context={
            "request": request,
            "version": version.__version__,
        },
    )


async def ui_login(request: Request, apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY)):
    """Validate credentials submitted by the login form.

    Args:
        request: Reference to the FastAPI request object.
        apikey: API key to authenticate the login request.

    Returns:
        JSONResponse:
        Returns 200 on success, 401/403 on failure.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.ui_login)

    token = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    expires = int(time.time()) + models.env.ui_lifetime
    database.upsert_ui_session(token, request.client.host, expires, models.session.fernet)
    LOGGER.info(
        "Connection received from host: %s, host-header: %s, x-fwd-host: %s",
        request.client.host,
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_basic)
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_basic)
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
        Returns a JSON response with the decoded (NOT decrypted) key-value pairs.
    """
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_basic)
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    raw = await api_endpoints.retrieve_secrets(table_name)
    # NOTE: There is no transit protection for the UI
    # Knowing transit_key_length and transit_time_bucket defeats the purpose of having a UI to simplify the usage
    decoded = {key: value.decode("UTF-8") for key, value in raw.items()}
    return JSONResponse(content={"encrypted_secrets": decoded})


async def ui_rename_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(api_endpoints.security),
):
    """Rename an existing table for the UI.

    Args:
        request: Reference to the FastAPI request object.
        table_name: Current name of the table to rename.
        session_token: Session token generated after a successful login.

    Returns:
        JSONResponse:
        Returns a JSON response indicating success or failure.
    """
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_advanced)
    body = await request.json()
    new_name = body.get("new_name", "").strip()
    if not new_name:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": "New table name cannot be empty"},
        )
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    if database.table_exists(new_name):
        return JSONResponse(
            status_code=HTTPStatus.CONFLICT.real,
            content={"detail": f"Table {new_name!r} already exists"},
        )
    try:
        database.rename_table(table_name, new_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]})
    return JSONResponse(content={"detail": "OK"})


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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_basic)
    if database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.CONFLICT.real,
            content={"detail": f"A table with name {table_name!r} already exists"},
        )
    try:
        database.create_table(table_name, ["key", "value"])
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]})
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_advanced)
    if not database.table_exists(table_name):
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Table {table_name!r} not found"},
        )
    try:
        database.drop_table(table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]})
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_advanced)
    body = await request.json()
    table_name = body.get("table_name", "default")
    key = body.get("key", "").strip()
    value = body.get("value", "").strip()
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_advanced)
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
                content={"detail": f"Unsupported payload_type {payload_type!r}; use json, yaml, or env"},
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
    await auth.validate(request, session_token, auth_type=auth.AuthType.ui_advanced)
    body = await request.json()
    table_name = body.get("table_name", "default")
    key = body.get("key", "").strip()
    if not key:
        return JSONResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            content={"detail": "Key cannot be empty"},
        )
    existing = await api_endpoints.retrieve_secret(key, table_name)
    if not existing:
        return JSONResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            content={"detail": f"Secret {key!r} not found"},
        )
    try:
        database.remove_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        return JSONResponse(status_code=HTTPStatus.BAD_REQUEST.real, content={"detail": error.args[0]})
    return JSONResponse(content={"detail": "OK"})
