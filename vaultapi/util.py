"""Utility module that provides helper functions for bulk secret import and transit decryption."""

import base64
import hashlib
import importlib
import json
import logging
import sqlite3
import time
from typing import Any, ByteString, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import dotenv_values

from . import database, models

importlib.reload(logging)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
HANDLER = logging.StreamHandler()
DEFAULT_FORMATTER = logging.Formatter(
    datefmt="%b-%d-%Y %I:%M:%S %p",
    fmt="%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s",
)
HANDLER.setFormatter(DEFAULT_FORMATTER)
LOGGER.addHandler(HANDLER)


def dotenv_to_table(table_name: str, dotenv_file: str, drop_existing: bool = False) -> None:
    """Load all key-value pairs from a ``.env`` file into a database table.

    When ``drop_existing`` is ``True`` the table is dropped and recreated before
    loading. Otherwise, existing secrets in the table are overwritten in-place.

    Args:
        table_name: Name of the destination table.
        dotenv_file: Path to the ``.env`` file to load.
        drop_existing: If ``True``, drop and recreate the table before importing.
    """
    if drop_existing and database.table_exists(table_name):
        LOGGER.info("Dropping table '%s' from '%s'", table_name, models.env.database)
        database.drop_table(table_name)
        database.create_table(table_name, ["key", "value"])
    else:
        try:
            if existing := database.get_table(table_name):
                LOGGER.warning(
                    "Table '%s' exists already in %s. %d secrets will be overwritten",
                    table_name,
                    models.env.database,
                    len(existing),
                )
        except sqlite3.OperationalError as error:
            if str(error) == f"no such table: {table_name}":
                LOGGER.info("Creating a new table '%s' in '%s'", table_name, models.env.database)
                database.create_table(table_name, ["key", "value"])
            else:
                raise
    env_vars = dotenv_values(dotenv_file)
    for key, value in env_vars.items():
        encrypted = models.session.fernet.encrypt(value.encode(encoding="UTF-8"))
        database.put_secret(key, encrypted, table_name)
    LOGGER.info(
        "%d secrets stored in the table %s, in the database %s.",
        len(env_vars),
        table_name,
        models.env.database,
    )


def transit_decrypt(ciphertext: str | ByteString) -> Dict[str, Any]:
    """Decrypt an AES-GCM transit-encrypted ciphertext using the API key and current time bucket.

    Args:
        ciphertext: Base64-encoded string or raw bytes to decrypt.

    Returns:
        Dict[str, Any]:
        Deserialized JSON payload from the decrypted ciphertext.
    """
    epoch = int(time.time()) // models.env.transit_time_bucket
    hash_object = hashlib.sha256(f"{epoch}.{models.env.apikey}".encode())
    aes_key = hash_object.digest()[: models.env.transit_key_length]
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
    return json.loads(decrypted)
