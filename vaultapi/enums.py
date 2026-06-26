try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):
        """Custom StrEnum object for python3.10."""


class APIRoutes(StrEnum):
    """Enums for API routes.

    >>> APIRoutes

    """

    # Base routes (no auth)
    root = "/"
    docs = "/docs"
    redoc = "/redoc"
    health = "/health"
    version = "/version"

    # Basic authentication (GET [OR] POST)
    get_secret = "/get-secret"
    get_table = "/get-table"
    list_tables = "/list-tables"
    create_table = "/create-table"

    # Advanced routes (PUT [OR] PATCH [OR] DELETE)
    put_secret = "/put-secret"
    delete_secret = "/delete-secret"
    rename_table = "/rename-table"
    delete_table = "/delete-table"


class UIRoutes(StrEnum):
    """Enums for UI routes.

    >>> UIRoutes

    """

    # Basic (no auth)
    root = "/"
    playground = "/playground"

    # Basic authentication
    ui_login = "/ui/login"
    ui_logout = "/ui/logout"
    ui_tables = "/ui/tables"
    ui_table = "/ui/table/{table_name}"
    ui_secret = "/ui/secret"
    ui_import = "/ui/import"
