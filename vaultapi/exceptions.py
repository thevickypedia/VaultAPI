"""Exceptions module that defines custom exception classes used across the Vault API."""

from fastapi.exceptions import HTTPException


class APIResponse(HTTPException):
    """Custom ``HTTPException`` from ``FastAPI`` to wrap an API response.

    >>> APIResponse

    """


class StartupError(EnvironmentError):
    """Custom ``StartupError`` to indicate an error during application startup.

    >>> StartupError

    """
