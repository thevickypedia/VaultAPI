import json
from typing import List, Tuple

from cryptography.fernet import Fernet

from . import models

UI_SESSION_TABLE = "ui_session"


def create_ui_session_table() -> None:
    """Create the ui_session table if it does not already exist.

    The table holds a single row with a Fernet-encrypted blob that encodes the
    active session token, the bound hostname, and the expiry timestamp.
    """
    with models.database.connection:
        models.database.connection.execute(
            f'CREATE TABLE IF NOT EXISTS "{UI_SESSION_TABLE}" (payload BLOB)'
        )
        models.database.connection.commit()


def upsert_ui_session(token: str, hostname: str, expires: int, fernet: Fernet) -> None:
    """Persist an active UI session, replacing any previous one.

    The stored blob is ``fernet.encrypt(json({"token": ..., "host": ..., "exp": ...}))``.
    Fernet provides authenticated encryption — tampering with the blob is detected on
    decrypt and raises an exception, which ``get_ui_session`` treats as "no valid session".

    Args:
        token: The opaque session token returned to the browser.
        hostname: ``request.client.host`` captured at login time.
        expires: Unix timestamp after which the session is invalid.
        fernet: Fernet instance from ``models.session.fernet``.
    """
    payload = fernet.encrypt(
        json.dumps({"token": token, "host": hostname, "exp": expires}).encode()
    )
    with models.database.connection:
        models.database.connection.execute(f'DELETE FROM "{UI_SESSION_TABLE}"')
        models.database.connection.execute(
            f'INSERT INTO "{UI_SESSION_TABLE}" (payload) VALUES (?)', (payload,)
        )
        models.database.connection.commit()


def get_ui_session(fernet: Fernet) -> dict | None:
    """Return the decrypted session record, or ``None`` if absent or tampered.

    Args:
        fernet: Fernet instance from ``models.session.fernet``.

    Returns:
        dict:
        ``{"token": str, "host": str, "exp": int}`` on success, ``None`` otherwise.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        row = cursor.execute(f'SELECT payload FROM "{UI_SESSION_TABLE}"').fetchone()
    if not row:
        return None
    try:
        return json.loads(fernet.decrypt(row[0]).decode())
    except Exception:
        return None


def delete_ui_session() -> None:
    """Remove all rows from the ui_session table, invalidating any active session."""
    with models.database.connection:
        models.database.connection.execute(f'DELETE FROM "{UI_SESSION_TABLE}"')
        models.database.connection.commit()


def table_exists(table_name: str) -> bool:
    """Function to check if a table exists in the database.

    Args:
        table_name: Name of the table to check.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        result = cursor.fetchone()
    if result:
        return True
    return False


def list_tables() -> List[str]:
    """Function to list all available tables in the database."""
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
    return [table[0] for table in tables if table[0] != UI_SESSION_TABLE]


def create_table(table_name: str, columns: List[str] | Tuple[str]) -> None:
    """Creates the table with the required columns.

    Args:
        table_name: Name of the table that has to be created.
        columns: List of columns that has to be created.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        # Use f-string or %s as table names cannot be parametrized
        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {table_name!r} ({', '.join(columns)})"
        )


def get_secret(key: str, table_name: str) -> str | None:
    """Function to retrieve secret from database.

    Args:
        key: Name of the secret to retrieve.
        table_name: Name of the table where the secret is stored.

    Returns:
        str:
        Returns the secret value.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        state = cursor.execute(
            f'SELECT value FROM "{table_name}" WHERE key=(?)', (key,)
        ).fetchone()
    if state and state[0]:
        return state[0]
    return None


def get_table(table_name: str) -> List[Tuple[str, str]]:
    """Function to retrieve all key-value pairs from a particular table in the database.

    Args:
        table_name: Name of the table where the secrets are stored.

    Returns:
        str:
        Returns the secret value.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        state = cursor.execute(f'SELECT * FROM "{table_name}"').fetchall()
    return state


def put_secret(key: str, value: str, table_name: str) -> None:
    """Function to add secret to the database.

    Args:
        key: Name of the secret to be stored.
        value: Value of the secret to be stored
        table_name: Name of the table where the secret is stored.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute(
            f'INSERT INTO "{table_name}" (key, value) VALUES (?,?)',
            (key, value),
        )
        models.database.connection.commit()


def remove_secret(key: str, table_name: str) -> None:
    """Function to remove a secret from the database.

    Args:
        key: Name of the secret to be removed.
        table_name: Name of the table where the secret is stored.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute(f'DELETE FROM "{table_name}" WHERE key=(?)', (key,))
        models.database.connection.commit()


def drop_table(table_name: str) -> None:
    """Function to drop a table from the database.

    Args:
        table_name: Name of the table to be dropped.
    """
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute(f'DROP TABLE IF EXISTS "{table_name}"')
        models.database.connection.commit()
