import logging
import sqlite3
from http import HTTPStatus
from typing import Dict, List

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import auth, database, exceptions, models, payload, rate_limit, transit

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


async def retrieve_secrets(table_name: str, keys: List[str] = None) -> Dict[str, str]:
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
    await auth.validate(request, apikey)
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
    await auth.validate(request, apikey)
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
    await auth.validate(request, apikey)
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
    await auth.validate(request, apikey)
    if not database.table_exists(data.table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table not found: {data.table_name!r}",
        )
    # Supports transit encrypted string
    if isinstance(data.secrets, str):
        data.secrets = transit.decrypt(data.secrets)
    for key, value in data.secrets.items():
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
    await auth.validate(request, apikey)
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
    await auth.validate(request, apikey)
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
    await auth.validate(request, apikey)
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
    """Healthcheck endpoint.

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


def get_all_routes() -> List[APIRoute]:
    """Get all the routes to be added for the API server.

    Returns:
        List[APIRoute]:
        Returns the routes as a list of APIRoute objects.
    """
    dependencies = [
        Depends(dependency=rate_limit.RateLimiter(each_rate_limit).init)
        for each_rate_limit in models.env.rate_limit
    ]
    routes = [
        APIRoute(path="/", endpoint=docs, methods=["GET"], include_in_schema=False),
        APIRoute(
            path="/health", endpoint=health, methods=["GET"], include_in_schema=False
        ),
        APIRoute(
            path="/get-secret",
            endpoint=get_secret,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/get-table",
            endpoint=get_table,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/list-tables",
            endpoint=list_tables,
            methods=["GET"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/put-secret",
            endpoint=put_secret,
            methods=["PUT"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/delete-secret",
            endpoint=delete_secret,
            methods=["DELETE"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/create-table",
            endpoint=create_table,
            methods=["POST"],
            dependencies=dependencies,
        ),
        APIRoute(
            path="/delete-table",
            endpoint=delete_table,
            methods=["DELETE"],
            dependencies=dependencies,
        ),
    ]
    return routes
