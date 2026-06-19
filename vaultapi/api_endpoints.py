import logging
import sqlite3
from http import HTTPStatus
from typing import Dict, List

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import auth, database, exceptions, models, payload, transit

LOGGER = logging.getLogger("uvicorn.default")
security = HTTPBearer()


async def retrieve_secret(key: str, table_name: str) -> str | None:
    """Retrieve an existing secret from a table in the database.

    Args:
        key: Name of the secret to retrieve.
        table_name: Name of the table where the secret is stored.

    Returns:
        str:
        Returns the secret value.
    """
    try:
        return database.get_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0]
        )


async def retrieve_secrets(
    table_name: str, keys: List[str] | None = None
) -> Dict[str, bytes]:
    """Retrieve multiple secrets from a table or retrieve the table as a whole.

    Args:
        table_name: Name of the table where the secret is stored.
        keys: List of keys for which the values have to be retrieved.

    Returns:
        Dict[str, str]:
        Returns the key-value pairs for secret key and it's value.
    """
    if keys:
        values = {}
        for key in keys:
            if value := await retrieve_secret(key, table_name):
                values[key] = value
        return values
    else:
        try:
            return dict(database.get_table(table_name))
        except sqlite3.OperationalError as error:
            LOGGER.error(error)
            raise exceptions.APIResponse(
                status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0]
            )


async def get_secret(
    request: Request,
    key: str,
    table_name: str = "default",
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to retrieve multiple secrets at a time.**

    **Args:**

        request: Reference to the FastAPI request object.
        keys: Comma separated list of secret names to be retrieved.
        table_name: Name of the table where the secrets are stored.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
    # keys = [key.strip() for key in keys.split(",") if key.strip()]
    keys = list(filter(None, map(str.strip, key.split(","))))
    keys_ct = len(keys)
    try:
        assert keys_ct, "Expected at least one key, received 0"
    except AssertionError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0]
        )
    if values := await retrieve_secrets(table_name, keys):
        values_ct = len(values)
        try:
            assert (
                values_ct == keys_ct
            ), f"Number of keys [{keys_ct}] requested didn't match the number of values [{values_ct}] retrieved."
            LOGGER.info("Secret value for %d (%s) were retrieved", keys_ct, keys)
            code = HTTPStatus.OK.real
        except AssertionError as error:
            LOGGER.warning(error)
            code = HTTPStatus.PARTIAL_CONTENT.real
        decrypted = {
            key: models.session.fernet.decrypt(value).decode(encoding="UTF-8")
            for key, value in values.items()
        }
        raise exceptions.APIResponse(
            status_code=code, detail=transit.encrypt(decrypted)
        )
    if keys_ct == 1:
        LOGGER.info("Secret value for '%s' NOT found in the datastore", keys[0])
    else:
        LOGGER.info(
            "Secret values for %d keys %s were NOT found in the datastore",
            keys_ct,
            keys,
        )
    raise exceptions.APIResponse(
        status_code=HTTPStatus.NOT_FOUND.real, detail=HTTPStatus.NOT_FOUND.phrase
    )


async def list_tables(
    request: Request,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to retrieve ALL available tables.**

    **Args:**

        request: Reference to the FastAPI request object.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=database.list_tables()
    )


async def get_table(
    request: Request,
    table_name: str = "default",
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to retrieve ALL the key-value pairs stored in a particular table.**

    **Args:**

        request: Reference to the FastAPI request object.
        table_name: Name of the table where the secrets are stored.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
    table_content = await retrieve_secrets(table_name)
    decrypted = {
        key: models.session.fernet.decrypt(value).decode(encoding="UTF-8")
        for key, value in table_content.items()
    }
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=transit.encrypt(decrypted)
    )


async def put_secret(
    request: Request,
    data: payload.PutSecret,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to add multiple secrets to a table in the database.**

    **Args:**

        request: Reference to the FastAPI request object.
        data: Payload with ``key``, ``value``, and ``table_name`` as body.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    if not database.table_exists(data.table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table not found: {data.table_name!r}",
        )
    # Supports transit encrypted string
    received_secrets = transit.decrypt(data.secrets) if isinstance(data.secrets, str) else data.secrets
    for key, value in received_secrets.items():
        encrypted = models.session.fernet.encrypt(value.encode(encoding="UTF-8"))
        database.put_secret(key=key, value=encrypted, table_name=data.table_name)
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase
    )


async def delete_secret(
    request: Request,
    data: payload.DeleteSecret,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to delete secrets from database.**

    **Args:**

        request: Reference to the FastAPI request object.
        data: Payload with ``key`` and ``table_name`` as body.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    if await retrieve_secret(data.key, data.table_name):
        LOGGER.info("Secret value for '%s' will be removed", data.key)
    else:
        LOGGER.warning("Secret value for '%s' NOT found", data.key)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real, detail=HTTPStatus.NOT_FOUND.phrase
        )
    try:
        database.remove_secret(key=data.key, table_name=data.table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.EXPECTATION_FAILED.real, detail=error.args[0]
        )
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase
    )


async def create_table(
    request: Request,
    table_name: str,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to create a new table in the database.**

    **Args:**

        request: Reference to the FastAPI request object.
        table_name: Name of the table to be created.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
    if database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.CONFLICT.real,
            detail=f"A table with name {table_name!r} already exists"
        )
    try:
        database.create_table(table_name, ["key", "value"])
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.EXPECTATION_FAILED.real, detail=error.args[0]
        )
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase
    )

# TODO: Remove redundancies between API endpoints and UI endpoints
async def rename_table(
    request: Request,
    table_name: str,
    data: payload.RenameTable,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to rename an existing table in the database.**

    **Args:**

        request: Reference to the FastAPI request object.
        table_name: Current name of the table to rename.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    if not data.new_name:
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail="New table name cannot be empty",
        )
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    if database.table_exists(data.new_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.CONFLICT.real,
            detail=f"Table {data.new_name!r} already exists",
        )
    try:
        database.rename_table(table_name, data.new_name)
        LOGGER.info("Table renamed '%s' -> '%s' successfully", table_name, data.new_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0]
        )
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase
    )


async def delete_table(
    request: Request,
    table_name: str,
    apikey: HTTPAuthorizationCredentials = Depends(security),
):
    """**API function to delete an existing table from the database.**

    **Args:**

        request: Reference to the FastAPI request object.
        table_name: Name of the table to be created.
        apikey: API Key to authenticate the request.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found!",
        )
    try:
        database.drop_table(table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(
            status_code=HTTPStatus.EXPECTATION_FAILED.real, detail=error.args[0]
        )
    raise exceptions.APIResponse(
        status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase
    )


async def health() -> Dict[str, str]:
    """Health check endpoint.

    Returns:
        Dict[str, str]:
        Returns the health response.
    """
    return {"STATUS": "OK"}


async def docs() -> RedirectResponse:
    """Redirect to docs page.

    Returns:
        RedirectResponse:
        Redirects the user to ``/docs`` page.
    """
    return RedirectResponse("/docs")
