import json
import logging
import sqlite3
from http import HTTPStatus
from typing import Dict, List, Optional

import yaml
from fastapi.security import HTTPBearer

from . import database, exceptions

LOGGER = logging.getLogger("uvicorn.default")
security = HTTPBearer()


async def retrieve_secret(key: str, table_name: str) -> Optional[bytes]:
    """Return raw encrypted value for key, or None if not found. Raises 400 on DB error."""
    try:
        return database.get_secret(key=key, table_name=table_name)
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


async def retrieve_secrets(table_name: str, keys: Optional[List[str]] = None) -> Dict[str, bytes]:
    """Return encrypted values for all keys in a table, or a subset if keys is given. Raises 400 on DB error."""
    if keys:
        return {key: value for key in keys if (value := await retrieve_secret(key, table_name))}
    try:
        return dict(database.get_table(table_name))
    except sqlite3.OperationalError as error:
        LOGGER.error(error)
        raise exceptions.APIResponse(status_code=HTTPStatus.BAD_REQUEST.real, detail=error.args[0])


def create_table(table_name: str) -> None:
    """Create a table. Raises 409 if it already exists, 400 on DB error."""
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
    """Drop a table. Raises 404 if not found, 400 on DB error."""
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
    """Rename a table. Raises 400/404/409 on validation errors, 400 on DB error."""
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
    """Remove a secret. Raises 400 if key is empty, 404 if not found, 400 on DB error."""
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
    """Parse a JSON, YAML, or .env string into a flat key-value dict. Raises 400 on any error."""
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
