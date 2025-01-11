from typing import List, Tuple

from . import models


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


def list_tables() -> List[str]:
    """Function to list all available tables in the database."""
    with models.database.connection:
        cursor = models.database.connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
    return [table[0] for table in tables]


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
