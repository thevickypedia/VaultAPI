"""API endpoints module that implements all authenticated REST operations for the Vault API.

1. Read-only endpoints (apikey based bearer token): get-secret, get-table, list-tables, create-table.
2. Write/Modify endpoints (apikey+secret based bearer token): put-secret, delete-secret, rename-table, delete-table.
3. Provides unauthenticated utility endpoints: health, version.
"""

import logging
from http import HTTPStatus
from typing import Dict

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials

from . import auth, core, enums, exceptions, models, payload, transit, version

LOGGER = logging.getLogger("uvicorn.default")


async def get_secret(
    request: Request,
    key: str,
    table_name: str = "default",
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to retrieve one or more secret(s) - transit encrypted.**

    **Args:**

        key: Single key or comma-separated list of keys to retrieve.
        table_name: Name of the table where the secrets are stored.

    **Raises:**

        APIResponse:
        - 200: Secrets found and returned (transit-encrypted).
        - 206: Partial content — some keys were not found.
        - 400: No valid keys provided.
        - 404: None of the requested keys were found.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_basic)
    keys = list(filter(None, map(str.strip, key.split(","))))
    keys_ct = len(keys)
    try:
        assert keys_ct, "Expected at least one key, received 0"
    except AssertionError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])
    if values := await core.retrieve_secrets(table_name, keys):
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
            key: models.session.fernet.decrypt(value).decode(encoding="UTF-8") for key, value in values.items()
        }
        raise exceptions.APIResponse(status_code=code, detail=transit.encrypt(decrypted))
    if keys_ct == 1:
        LOGGER.info("Secret value for '%s' NOT found in the datastore", keys[0])
    else:
        LOGGER.info("Secret values for %d keys %s were NOT found in the datastore", keys_ct, keys)
    raise exceptions.APIResponse(status_code=HTTPStatus.NOT_FOUND.real, detail=HTTPStatus.NOT_FOUND.phrase)


async def list_tables(
    request: Request,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to get ALL table names.**

    **Raises:**

        APIResponse:
        - 200: Table list returned successfully.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_basic)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=core.database.list_tables())


async def get_table(
    request: Request,
    table_name: str = "default",
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to get ALL secrets in a table - transit encrypted.**

    **Args:**

        table_name: Name of the table where the secrets are stored.

    **Raises:**

        APIResponse:
        - 200: All secrets returned (transit-encrypted).
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_basic)
    table_content = await core.retrieve_secrets(table_name)
    decrypted = {
        key: models.session.fernet.decrypt(value).decode(encoding="UTF-8") for key, value in table_content.items()
    }
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=transit.encrypt(decrypted))


async def put_secret(
    request: Request,
    data: payload.PutSecret,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to add or update secrets in a table, accepting plain or transit-encrypted payloads.**

    **Args:**

        data: Request body containing ``secrets`` (plain dict or transit-encrypted string) and ``table_name``.

    **Raises:**

        APIResponse:
        - 200: Secrets stored successfully.
        - 404: Table not found.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_advanced)
    if not core.database.table_exists(data.table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table not found: {data.table_name!r}",
        )
    received_secrets = transit.decrypt(data.secrets) if isinstance(data.secrets, str) else data.secrets
    for key, value in received_secrets.items():
        encrypted = models.session.fernet.encrypt(value.encode(encoding="UTF-8"))
        core.database.put_secret(key=key, value=encrypted, table_name=data.table_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def delete_secret(
    request: Request,
    data: payload.DeleteSecret,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to delete a secret key from a table in the database.**

    **Args:**

        data: Request body containing ``key`` and ``table_name``.

    **Raises:**

        APIResponse:
        - 200: Secret deleted successfully.
        - 404: Secret or table not found.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_advanced)
    await core.remove_secret(data.key, data.table_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def create_table(
    request: Request,
    table_name: str,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to create a new table in the database.**

    **Args:**

        table_name: Name of the table to be created.

    **Raises:**

        APIResponse:
        - 200: Table created successfully.
        - 409: Table already exists.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_basic)
    core.create_table(table_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def rename_table(
    request: Request,
    table_name: str,
    data: payload.RenameTable,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to rename an existing table in the database.**

    **Args:**

        table_name: Current name of the table to rename.
        data: Request body containing ``new_name``.

    **Raises:**

        APIResponse:
        - 200: Table renamed successfully.
        - 400: New name is empty.
        - 404: Table not found.
        - 409: A table with the new name already exists.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_advanced)
    core.rename_table(table_name, data.new_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def delete_table(
    request: Request,
    table_name: str,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to delete a table in the database.**

    **Args:**

        table_name: Name of the table to delete.

    **Raises:**

        APIResponse:
        - 200: Table deleted successfully.
        - 404: Table not found.
    """
    await auth.validate(request, apikey, auth_type=enums.AuthType.api_advanced)
    core.drop_table(table_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def health() -> Dict[str, str]:
    """Return a simple health check response.

    Returns:
        Dict[str, str]:
        Always returns ``{"STATUS": "OK"}``.
    """
    return {"STATUS": "OK"}


async def get_version() -> str:
    """Return the current version of the Vault API.

    Returns:
        str:
        Version string of the Vault API.
    """
    return version.__version__
