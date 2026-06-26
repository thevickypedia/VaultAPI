import logging
from http import HTTPStatus
from typing import Dict

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials

from . import auth, core, exceptions, models, payload, transit, version

LOGGER = logging.getLogger("uvicorn.default")


async def get_secret(
    request: Request,
    key: str,
    table_name: str = "default",
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to retrieve one or more secret(s) - transit encrypted.**

    **Args:**

        key: Single key or a comma separated list of secrets to be retrieved.
        table_name: Name of the table where the secrets are stored.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
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
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
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
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
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
    """**API function to add or update secret(s) in a table in the database.**

    **Args:**

        data: Payload with ``key``, ``value``, and ``table_name`` as body.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
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
    """**API function to delete a secret from a table in the database.**

    **Args:**

        data: Payload with ``key`` and ``table_name`` as body.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
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
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_basic)
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

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    core.rename_table(table_name, data.new_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def delete_table(
    request: Request,
    table_name: str,
    apikey: HTTPAuthorizationCredentials = Depends(auth.SECURITY),
):
    """**API function to delete a table in the database.**

    **Args:**

        table_name: Name of the table to be created.

    **Raises:**

        APIResponse:
        Raises the HTTPStatus object with a status code and detail as response.
    """
    await auth.validate(request, apikey, auth_type=auth.AuthType.api_advanced)
    core.drop_table(table_name)
    raise exceptions.APIResponse(status_code=HTTPStatus.OK.real, detail=HTTPStatus.OK.phrase)


async def health() -> Dict[str, str]:
    """Health check endpoint.

    Returns:
        Dict[str, str]:
        Returns the health response.
    """
    return {"STATUS": "OK"}


async def get_version() -> str:
    """Endpoint to get the current version of the Vault API.

    Returns:
        str:
        Returns the version string of the Vault API.
    """
    return version.__version__
