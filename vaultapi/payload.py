from typing import Dict

from pydantic import BaseModel


class DeleteSecret(BaseModel):
    """Payload for delete-secret API call.

    >>> DeleteSecret

    """

    key: str
    table_name: str = "default"


class PutSecret(BaseModel):
    """Payload for put-secrets API call.

    >>> PutSecret

    """

    secrets: Dict[str, str] | str
    table_name: str = "default"


class RenameTable(BaseModel):
    """Payload for rename-table API call.

    >>> RenameTable

    """

    new_name: str
