"""Core module is the common layer for Vault API that includes functionalities used by both API and UI endpoints."""

import json
import logging
import sqlite3
from http import HTTPStatus
from typing import Dict, List, Optional

import yaml

from . import database, exceptions

LOGGER = logging.getLogger("uvicorn.default")


async def retrieve_secret(key: str, table_name: str) -> Optional[str]:
    """Return the raw encrypted value for a single key, or ``None`` if not found.

    Args:
        key: Key to look up.
        table_name: Table name where the secret is stored.

    Returns:
        str:
        Raw encrypted value, or ``None`` if the key does not exist.

    Raises:
        APIResponse:
        - 400: On SQLite operational error.
        - 404: ``key`` does not exist.
    """
    try:
        return database.get_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


async def retrieve_secrets(table_name: str, keys: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
    """Return a mapping of key → encrypted value for the given table.

    When ``keys`` is provided only those keys are fetched; otherwise all rows
    in the table are returned.

    Args:
        table_name: Table name where the secrets are stored.
        keys: Optional subset of keys to retrieve. Omit to return the full table.

    Returns:
        Dict[str, bytes]:
        Mapping of key names to their raw encrypted values.

    Raises:
        APIResponse:
        - 400: On SQLite operational error.
    """
    if keys:
        return {key: value for key in keys if (value := await retrieve_secret(key, table_name))}
    try:
        return dict(database.get_table(table_name))
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


def create_table(table_name: str) -> None:
    """Create a table, raising 409 if it already exists or 400 on a DB error.

    Args:
        table_name: Name of the table to create.

    Raises:
        APIResponse:
        - 409: A table with that name already exists.
        - 400: On SQLite operational error.
    """
    if database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.CONFLICT.real,
            detail=f"A table with name {table_name!r} already exists",
        )
    try:
        database.create_table(table_name, ["key", "value"])
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


def drop_table(table_name: str) -> None:
    """Drop a table, raising 404 if it does not exist or 400 on a DB error.

    Args:
        table_name: Name of the table to drop.

    Raises:
        APIResponse:
        - 404: Table not found.
        - 400: On SQLite operational error.
    """
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    try:
        database.drop_table(table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


def rename_table(table_name: str, new_name: str) -> None:
    """Rename a table after validating the old and new names.

    Args:
        table_name: Current name of the table.
        new_name: Desired new name.

    Raises:
        APIResponse:
        - 400: ``new_name`` is empty.
        - 404: ``table_name`` does not exist.
        - 409: A table named ``new_name`` already exists.
        - 400: On SQLite operational error.
    """
    if not new_name:
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail="New table name cannot be empty",
        )
    if not database.table_exists(table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Table {table_name!r} not found",
        )
    if database.table_exists(new_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.CONFLICT.real,
            detail=f"Table {new_name!r} already exists",
        )
    try:
        database.rename_table(table_name, new_name)
        LOGGER.info("Table renamed '%s' -> '%s' successfully", table_name, new_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


async def remove_secret(key: str, table_name: str) -> None:
    """Delete a secret from a table after validating its existence.

    Args:
        key: Key of the secret to remove.
        table_name: Name of the table that contains the secret.

    Raises:
        APIResponse:
        - 400: ``key`` is empty.
        - 404: The secret does not exist.
        - 400: On SQLite operational error.
    """
    if not key:
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail="Key cannot be empty",
        )
    if not await retrieve_secret(key, table_name):
        raise exceptions.APIResponse(
            status_code=HTTPStatus.NOT_FOUND.real,
            detail=f"Secret {key!r} not found",
        )
    try:
        LOGGER.info("Secret value for '%s' will be removed", key)
        database.remove_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


def parse_import_payload(payload: str, payload_type: str) -> Dict[str, str]:
    """Parse a JSON, YAML, or ``.env`` string into a flat key-value dict.

    See Also:
        Supported ``payload_type`` values:
        - ``"json"``: Must be a flat JSON object.
        - ``"yaml"``: Must be a flat YAML mapping.
        - ``"env"``: Standard dotenv format; comments and blank lines are skipped.

    Args:
        payload: Raw payload string to parse.
        payload_type: Format indicator — one of ``"json"``, ``"yaml"``, or ``"env"``.

    Returns:
        Dict[str, str]:
        Flat mapping of string keys to string values extracted from the payload.

    Raises:
        APIResponse:
        - 400: Unsupported ``payload_type``, malformed payload, non-dict structure, or empty result.
    """
    try:
        if payload_type == "json":
            parsed = json.loads(payload)
            if not isinstance(parsed, dict):
                raise exceptions.APIResponse(
                    status_code=HTTPStatus.BAD_REQUEST.real,
                    detail="JSON payload must be a flat object",
                )
            pairs = {str(k): str(v) for k, v in parsed.items()}
        elif payload_type == "yaml":
            parsed = yaml.safe_load(payload)
            if not isinstance(parsed, dict):
                raise exceptions.APIResponse(
                    status_code=HTTPStatus.BAD_REQUEST.real,
                    detail="YAML payload must be a flat mapping",
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
            raise exceptions.APIResponse(
                status_code=HTTPStatus.BAD_REQUEST.real,
                detail=f"Unsupported payload_type {payload_type!r}; use json, yaml, or env",
            )
    except exceptions.APIResponse:
        raise
    except Exception as error:
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail=f"Failed to parse payload: {error}",
        )
    if not pairs:
        raise exceptions.APIResponse(
            status_code=HTTPStatus.BAD_REQUEST.real,
            detail="No key-value pairs found in payload",
        )
    return pairs
