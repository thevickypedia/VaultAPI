"""Database module that provides all SQLite read/write operations for secrets, sessions, and auth tracking.

1. Manages the UI session table (single active session stored as a Fernet-encrypted blob).
2. Manages the blocked-hosts table for failed authentication rate-limiting.
3. Provides CRUD helpers for user-defined secret tables.
"""

import json
import logging
import time
from collections import OrderedDict
from typing import List, Tuple

from cryptography.fernet import Fernet

from . import models

LOGGER = logging.getLogger("uvicorn.default")
UI_SESSION_TABLE = "ui_session"
BLOCKED_HOSTS_TABLE = "blocked_hosts"
FAILED_AUTH_LIMIT = 3

COOLOFF_THRESHOLDS: OrderedDict[int, int] = OrderedDict([(10, 86400), (5, 900), (3, 300)])


def create_auth_tables() -> None:
    """Create the UI session and blocked-hosts tables if they do not already exist."""
    with models.auth_database.connection as conn:
        conn.execute(f'CREATE TABLE IF NOT EXISTS "{UI_SESSION_TABLE}" (payload BLOB)')
        conn.execute(
            f'CREATE TABLE IF NOT EXISTS "{BLOCKED_HOSTS_TABLE}" '
            f"(host TEXT PRIMARY KEY, failed_auth INTEGER NOT NULL DEFAULT 0, "
            f"blocked_until INTEGER)"
        )
        conn.commit()


def upsert_ui_session(token: str, hostname: str, expires: int, fernet: Fernet) -> None:
    """Persist an active UI session, replacing any previous one.

    The stored blob is ``fernet.encrypt(json({"token": ..., "host": ..., "exp": ...}))``.
    Fernet provides authenticated encryption — tampering with the blob is detected on
    decrypt and raises an exception, which ``get_ui_session`` treats as "no valid session".

    Args:
        token: Opaque session token returned to the browser.
        hostname: ``request.client.host`` captured at login time.
        expires: Unix timestamp after which the session is considered invalid.
        fernet: Fernet instance from ``models.session.fernet``.
    """
    payload = fernet.encrypt(json.dumps({"token": token, "host": hostname, "exp": expires}).encode())
    with models.auth_database.connection as conn:
        conn.execute(f'DELETE FROM "{UI_SESSION_TABLE}"')
        conn.execute(f'INSERT INTO "{UI_SESSION_TABLE}" (payload) VALUES (?)', (payload,))
        conn.commit()


def get_ui_session(fernet: Fernet) -> dict | None:
    """Return the decrypted session record, or ``None`` if absent or tampered.

    Args:
        fernet: Fernet instance from ``models.session.fernet``.

    Returns:
        dict:
        ``{"token": str, "host": str, "exp": int}`` on success, ``None`` otherwise.
    """
    with models.auth_database.connection as conn:
        row = conn.cursor().execute(f'SELECT payload FROM "{UI_SESSION_TABLE}"').fetchone()
    if not row:
        return None
    try:
        return json.loads(fernet.decrypt(row[0]).decode())
    except Exception as error:
        LOGGER.error(error)
        return None


def delete_ui_session() -> None:
    """Remove all rows from the UI session table, invalidating any active session."""
    with models.auth_database.connection as conn:
        conn.execute(f'DELETE FROM "{UI_SESSION_TABLE}"')
        conn.commit()


def get_blocked_until(host: str) -> models.AuthCounter | None:
    """Return the auth counter for a blocked host, or ``None`` if the host is not blocked.

    If a cooloff entry exists but has already expired it is cleared and ``None`` is returned.

    Args:
        host: Client IP address to check.

    Returns:
        models.AuthCounter | None:
        ``AuthCounter`` with ``count`` and ``blocked_until`` if the host is currently
        blocked, ``None`` otherwise.
    """
    with models.auth_database.connection as conn:
        row = (
            conn.cursor()
            .execute(
                f'SELECT failed_auth, blocked_until FROM "{BLOCKED_HOSTS_TABLE}" WHERE host = ?',
                (host,),
            )
            .fetchone()
        )
    if not row:
        return None
    count, blocked_until = row
    if blocked_until is None:
        return None
    if int(time.time()) >= blocked_until:
        # Clear the timer but keep the failure count so the tier escalates on
        # subsequent failures; only a successful login resets the counter.
        with models.auth_database.connection as conn:
            conn.execute(
                f'UPDATE "{BLOCKED_HOSTS_TABLE}" SET blocked_until = NULL WHERE host = ?',
                (host,),
            )
            conn.commit()
        return None
    return models.AuthCounter(
        count=count,
        blocked_until=blocked_until,
    )


def is_host_blocked(host: str) -> bool:
    """Return ``True`` if the host is currently within an active cooloff window.

    Args:
        host: Client IP address to check.

    Returns:
        bool:
        ``True`` if blocked, ``False`` otherwise.
    """
    return get_blocked_until(host) is not None


def remove_blocked_host(host: str) -> None:
    """Delete a host's entry from the blocked-hosts table entirely.

    Args:
        host: Client IP address to remove.
    """
    with models.auth_database.connection as conn:
        conn.execute(f'DELETE FROM "{BLOCKED_HOSTS_TABLE}" WHERE host = ?', (host,))
        conn.commit()


def increment_failed_auth(host: str) -> None:
    """Increment the failed-authentication counter for a host and apply a cooloff if a threshold is crossed.

    Inserts the host with ``failed_auth = 1`` if it does not yet exist. Sets
    ``blocked_until`` when the cumulative count reaches a threshold defined in
    ``COOLOFF_THRESHOLDS``.

    Args:
        host: Client IP address that failed authentication.
    """
    with models.auth_database.connection as conn:
        conn.execute(
            f'INSERT INTO "{BLOCKED_HOSTS_TABLE}" (host, failed_auth) VALUES (?, 1) '
            f"ON CONFLICT(host) DO UPDATE SET failed_auth = failed_auth + 1",
            (host,),
        )
        conn.commit()
        new_count = (
            conn.cursor()
            .execute(
                f'SELECT failed_auth FROM "{BLOCKED_HOSTS_TABLE}" WHERE host = ?',
                (host,),
            )
            .fetchone()[0]
        )
    blocked_until = None
    for min_count, duration in COOLOFF_THRESHOLDS.items():
        if new_count >= min_count:
            blocked_until = int(time.time()) + duration
            break
    if blocked_until is not None:
        with conn:
            conn.execute(
                f'UPDATE "{BLOCKED_HOSTS_TABLE}" SET blocked_until = ? WHERE host = ?',
                (blocked_until, host),
            )
            conn.commit()


def reset_failed_auth(host: str) -> None:
    """Reset the failed-authentication counter to zero after a successful login.

    Args:
        host: Client IP address to reset.
    """
    with models.auth_database.connection as conn:
        conn.execute(
            f'UPDATE "{BLOCKED_HOSTS_TABLE}" SET failed_auth = 0, blocked_until = NULL WHERE host = ?',
            (host,),
        )
        conn.commit()


def table_exists(table_name: str) -> bool:
    """Check whether a user-defined table exists in the secrets database.

    Args:
        table_name: Name of the table to check.

    Returns:
        bool:
        ``True`` if the table exists, ``False`` otherwise.
    """
    with models.database.connection as conn:
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
    if result:
        return True
    return False


def list_tables() -> List[str]:
    """Return the names of all user-defined tables in the secrets database.

    Returns:
        List[str]:
        List of table names.
    """
    with models.database.connection as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    return [table[0] for table in tables]


def create_table(table_name: str, columns: List[str] | Tuple[str]) -> None:
    """Create a table with the specified columns (no-op if it already exists).

    Args:
        table_name: Name of the table to create.
        columns: Column definitions (e.g. ``["key", "value"]``).
    """
    with models.database.connection as conn:
        # Use f-string or %s as table names cannot be parametrized
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table_name!r} ({', '.join(columns)})")


def get_secret(key: str, table_name: str) -> str | None:
    """Retrieve a single encrypted secret value by key.

    Args:
        key: Name of the secret to retrieve.
        table_name: Name of the table where the secret is stored.

    Returns:
        str:
        Encrypted secret value, or ``None`` if the key does not exist.
    """
    with models.database.connection as conn:
        state = conn.execute(f'SELECT value FROM "{table_name}" WHERE key=(?)', (key,)).fetchone()
    if state and state[0]:
        return state[0]
    return None


def get_table(table_name: str) -> List[Tuple[str, str]]:
    """Retrieve all key-value pairs from a table.

    Args:
        table_name: Name of the table to read.

    Returns:
        List[Tuple[str, str]]:
        List of ``(key, encrypted_value)`` tuples.
    """
    with models.database.connection as conn:
        state = conn.execute(f'SELECT * FROM "{table_name}"').fetchall()
    return state


def put_secret(key: str, value: str, table_name: str) -> None:
    """Insert or overwrite a secret in the database.

    Args:
        key: Name of the secret.
        value: Encrypted value to store.
        table_name: Name of the table where the secret is stored.
    """
    with models.database.connection as conn:
        conn.execute(
            f'INSERT INTO "{table_name}" (key, value) VALUES (?,?)',
            (key, value),
        )
        conn.commit()


def remove_secret(key: str, table_name: str) -> None:
    """Delete a secret from a table.

    Args:
        key: Name of the secret to remove.
        table_name: Name of the table where the secret is stored.
    """
    with models.database.connection as conn:
        conn.execute(f'DELETE FROM "{table_name}" WHERE key=(?)', (key,))
        conn.commit()


def drop_table(table_name: str) -> None:
    """Drop a table from the database.

    Args:
        table_name: Name of the table to drop.
    """
    with models.database.connection as conn:
        conn.execute(f'DROP TABLE IF EXISTS "{table_name}"')
        conn.commit()


def rename_table(old_name: str, new_name: str) -> None:
    """Rename a table in the database.

    Args:
        old_name: Current name of the table.
        new_name: New name for the table.
    """
    with models.database.connection as conn:
        conn.execute(f'ALTER TABLE "{old_name}" RENAME TO "{new_name}"')
        conn.commit()
