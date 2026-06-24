import base64
import logging
import os
import pathlib
import time
from datetime import datetime
from http import HTTPStatus

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates

from . import auth, core, database, exceptions, models, version

templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")
LOGGER = logging.getLogger("uvicorn.default")


async def index(request: Request):
    """Endpoint to serve the UI landing page.

    Returns:
        HTMLResponse:
        Returns the HTML content for the UI.
    """
    # Manually check for blocked since no auth is required for this endpoint
    await auth.blocked(request.client.host)
    return templates.TemplateResponse(
        name="index.html",
        request=request,
        context={"request": request, "version": version.__version__},
    )


async def signature_page(request: Request):
    """Serve the signature generator page."""
    await auth.blocked(request.client.host)
    return templates.TemplateResponse(
        name="signature.html",
        request=request,
        context={"request": request, "version": version.__version__},
    )


async def ui_login(request: Request, apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY)):
    """Validate the login credentials and issue a session token.

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
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """Invalidate the active UI session.

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
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
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
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """Get all secrets (no transit encryption) in a table, for the UI.

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
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    raw = await core.retrieve_secrets(table_name)
    decoded = {key: value.decode("UTF-8") for key, value in raw.items()}
    return JSONResponse(content={"encrypted_secrets": decoded})


async def ui_rename_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """Rename a table for the UI.

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
    core.rename_table(table_name, new_name)
    return JSONResponse(content={"detail": "OK"})


async def ui_create_table(request: Request, table_name: str, session_token=Depends(auth.SECURITY)):
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
    core.create_table(table_name)
    return JSONResponse(content={"detail": "OK"})


async def ui_delete_table(
    request: Request,
    table_name: str,
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
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
    core.drop_table(table_name)
    return JSONResponse(content={"detail": "OK"})


async def ui_put_secret(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
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
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail="Key cannot be empty",
        )
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    encrypted = models.session.fernet.encrypt(value.encode("UTF-8"))
    database.put_secret(key=key, value=encrypted, table_name=table_name)
    return JSONResponse(content={"detail": "OK"})


async def ui_import_secrets(
    request: Request,
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
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
    payload_str = body.get("payload", "")
    payload_type = body.get("payload_type", "").lower()
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    pairs = core.parse_import_payload(payload_str, payload_type)
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
    session_token: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
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
    await core.remove_secret(key, table_name)
    return JSONResponse(content={"detail": "OK"})
