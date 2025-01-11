import pathlib
import re
import socket
import sqlite3
from typing import Any, Dict, List, Set

from cryptography.fernet import Fernet
from pydantic import (
    BaseModel,
    Field,
    FilePath,
    HttpUrl,
    NewPath,
    PositiveInt,
    field_validator,
)
from pydantic_settings import BaseSettings


def complexity_checker(secret: str) -> None:
    """Verifies the strength of a secret.

    See Also:
        A secret is considered strong if it at least has:

        - 32 characters
        - 1 digit
        - 1 symbol
        - 1 uppercase letter
        - 1 lowercase letter

    Raises:
        AssertionError: When at least 1 of the above conditions fail to match.
    """
    # calculates the length
    assert (
        len(secret) >= 32
    ), f"secret length must be at least 32, received {len(secret)}"

    # searches for digits
    assert re.search(r"\d", secret), "secret must include an integer"

    # searches for uppercase
    assert re.search(
        r"[A-Z]", secret
    ), "secret must include at least one uppercase letter"

    # searches for lowercase
    assert re.search(
        r"[a-z]", secret
    ), "secret must include at least one lowercase letter"

    # searches for symbols
    assert re.search(
        r"[ !@#$%^&*()_='+,-./[\\\]`{|}~" + r'"]', secret
    ), "secret must contain at least one special character"


class Database:
    """Creates a connection and instantiates the cursor.

    >>> Database

    Args:
        filepath: Name of the database file.
        timeout: Timeout for the connection to database.
    """

    def __init__(self, filepath: FilePath | str, timeout: int = 10):
        """Instantiates the class ``Database`` to create a connection and a cursor."""
        if not filepath.endswith(".db"):
            filepath = filepath + ".db"
        self.connection = sqlite3.connect(
            database=filepath, check_same_thread=False, timeout=timeout
        )


database: Database = Database  # noqa: PyTypeChecker


class RateLimit(BaseModel):
    """Object to store the rate limit settings.

    >>> RateLimit

    """

    max_requests: PositiveInt
    seconds: PositiveInt


class Session(BaseModel):
    """Object to store session information.

    >>> Session

    """

    fernet: Fernet | None = None
    info: Dict[str, str] = Field(default_factory=dict)
    rps: Dict[str, int] = Field(default_factory=dict)
    allowed_origins: Set[str] = Field(default_factory=set)

    class Config:
        """Config to allow arbitrary types."""

        arbitrary_types_allowed = True


class EnvConfig(BaseSettings):
    """Object to load environment variables.

    >>> EnvConfig

    """

    apikey: str
    secret: str
    transit_key_length: PositiveInt = 32
    transit_time_bucket: PositiveInt = 60
    database: FilePath | NewPath | str = Field("secrets.db", pattern=".*.db$")
    host: str = socket.gethostbyname("localhost") or "0.0.0.0"
    port: PositiveInt = 9010
    workers: PositiveInt = 1
    log_config: FilePath | Dict[str, Any] | None = None
    allowed_origins: HttpUrl | List[HttpUrl] = Field(default_factory=list)
    allowed_ip_range: List[str] = Field(default_factory=list)
    # This is a base rate limit configuration
    rate_limit: RateLimit | List[RateLimit] = Field(
        default=[
            # Burst limit: Prevents excessive load on the server
            {
                "max_requests": 5,
                "seconds": 2,
            },
            # Sustained limit: Prevents too many trial and errors
            {
                "max_requests": 10,
                "seconds": 30,
            },
        ]
    )

    @field_validator("allowed_origins", mode="after", check_fields=True)
    def validate_allowed_origins(
        cls, value: HttpUrl | List[HttpUrl]  # noqa: PyMethodParameters
    ) -> List[HttpUrl]:
        """Validate allowed origins to enable CORS policy."""
        if isinstance(value, list):
            return value
        return [value]

    @field_validator("allowed_ip_range", mode="after", check_fields=True)
    def validate_allowed_ip_range(
        cls, value: List[str]  # noqa: PyMethodParameters
    ) -> List[str]:
        """Validate allowed IP range to whitelist."""
        for ip_range in value:
            try:
                assert (
                    len(ip_range.split(".")) > 1
                ), f"Expected a valid IP address, received {ip_range}"
                assert (
                    len(ip_range.split(".")[-1].split("-")) == 2
                ), f"Expected a valid IP range, received {ip_range}"
            except AssertionError as error:
                exc = f"{error}\n\tInput should be a list of IP range (eg: ['192.168.1.10-19', '10.120.1.5-35'])"
                raise ValueError(exc)
        return value

    @field_validator("apikey", mode="after")
    def validate_apikey(cls, value: str) -> str | None:  # noqa: PyMethodParameters
        """Validate API key for complexity."""
        try:
            complexity_checker(value)
        except AssertionError as error:
            raise ValueError(error.__str__())
        return value

    @field_validator("secret", mode="after")
    def validate_api_secret(cls, value: str) -> str:  # noqa: PyMethodParameters
        """Validate API secret to Fernet compatible."""
        try:
            Fernet(value)
        except ValueError as error:
            exc = f"{error}\n\tConsider using 'vaultapi keygen' command to generate a valid secret."
            raise ValueError(exc)
        return value

    @classmethod
    def from_env_file(cls, env_file: pathlib.Path) -> "EnvConfig":
        """Create Settings instance from environment file.

        Args:
            env_file: Name of the env file.

        Returns:
            EnvConfig:
            Loads the ``EnvConfig`` model.
        """
        return cls(_env_file=env_file)

    class Config:
        """Extra configuration for EnvConfig object."""

        extra = "ignore"
        hide_input_in_errors = True
        arbitrary_types_allowed = True


# noinspection PyTypeChecker
env: EnvConfig = EnvConfig
session = Session()
