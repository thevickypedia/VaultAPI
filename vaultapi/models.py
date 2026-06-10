import json
import logging
import os
import pathlib
import re
import socket
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, NoReturn, Set

import yaml
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

from . import exceptions

LOGGER = logging.getLogger("uvicorn.default")


def complexity_checker(secret: str, max_len: int = 32) -> None:
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
        len(secret) >= max_len
    ), f"secret length must be at least {max_len}, received {len(secret)}"

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


def validate_totp_secret(token) -> None | NoReturn:
    """Validate the provided TOTP secret token."""
    totp = pyotp.TOTP(token)
    # Sampler can also be generated with totp.now()
    now = datetime.now()
    sampler = totp.generate_otp(totp.timecode(now))
    assert totp.verify(sampler, for_time=now), "Invalid authenticatorToken!"


class Database:
    """Creates a connection and instantiates the cursor.

    >>> Database

    Args:
        filepath: Name of the database file.
        timeout: Timeout for the connection to database.
    """

    def __init__(self, filepath: FilePath | str, timeout: int = 10):
        """Instantiates the class ``Database`` to create a connection and a cursor."""
        db_path = pathlib.Path(filepath)
        if db_path.suffix != ".db":
            db_path = db_path.with_suffix(".db")

        # sqlite can create files, but not missing parent directories
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.touch(exist_ok=True)

        self.connection = sqlite3.connect(
            database=str(db_path), check_same_thread=False, timeout=timeout
        )


class RateLimit(BaseModel):
    """Object to store the rate limit settings.

    >>> RateLimit

    """

    max_requests: PositiveInt
    seconds: PositiveInt


# noinspection PyDataclass
class Session(BaseModel):
    """Object to store session information.

    >>> Session

    """

    fernet: Fernet | None = None
    info: Dict[str, str] = Field(default_factory=dict)
    rps: Dict[str, int] = Field(default_factory=dict)
    blocked_hosts: Set[str] = Field(default_factory=set)

    class Config:
        """Config to allow arbitrary types."""

        arbitrary_types_allowed = True


# noinspection PyMethodParameters,PyDataclass
class EnvConfig(BaseSettings):
    """Object to load environment variables.

    >>> EnvConfig

    """

    apikey: str
    secret: str
    transit_key_length: PositiveInt = 32
    transit_time_bucket: PositiveInt = Field(60, ge=30, le=300)  # 30s to 5m
    database: FilePath | NewPath | str = Field("secrets.db", pattern=".*.db$")
    host: str = socket.gethostbyname("localhost") or "0.0.0.0"
    port: PositiveInt = 9010
    workers: PositiveInt = 1
    enable_ui: bool = False
    totp_token: str | None = None
    ui_lifetime: PositiveInt = Field(900, ge=300, le=3_600)  # 5m to 1h
    log_config: FilePath | Dict[str, Any] | None = None
    allowed_origins: HttpUrl | List[HttpUrl] = Field(default_factory=list)
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

    @field_validator("transit_key_length", mode="after", check_fields=True)
    def validate_transit_key_length(cls, value: PositiveInt) -> PositiveInt | NoReturn:
        """Validate transit key length."""
        if value in (16, 24, 32):
            return value
        raise ValueError("Transit key length (AES) must be one of 16, 24, or 32 bytes.")

    @field_validator("apikey", mode="after")
    def validate_apikey(cls, value: str) -> str | None:
        """Validate API key for complexity."""
        try:
            complexity_checker(value)
        except AssertionError as error:
            raise ValueError(error.__str__())
        return value

    @field_validator("secret", mode="after")
    def validate_api_secret(cls, value: str) -> str:
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
        # noinspection PyArgumentList
        return cls(_env_file=env_file)

    class Config:
        """Extra configuration for EnvConfig object."""

        extra = "ignore"
        hide_input_in_errors = True
        arbitrary_types_allowed = True


def envfile_loader(filename: str | os.PathLike) -> EnvConfig:
    """Loads environment variables based on filetypes.

    Args:
        filename: Filename from where env vars have to be loaded.

    Returns:
        EnvConfig:
        Returns a reference to the ``EnvConfig`` object.
    """
    env_file = pathlib.Path(filename)
    if env_file.suffix.lower() == ".json":
        with open(env_file) as stream:
            env_data = json.load(stream)
        return EnvConfig(**{k.lower(): v for k, v in env_data.items()})
    elif env_file.suffix.lower() in (".yaml", ".yml"):
        with open(env_file) as stream:
            env_data = yaml.load(stream, yaml.FullLoader)
        return EnvConfig(**{k.lower(): v for k, v in env_data.items()})
    elif not env_file.suffix or env_file.suffix.lower() in (
        ".text",
        ".txt",
        ".env",
        "",
    ):
        return EnvConfig.from_env_file(env_file)
    else:
        raise ValueError(
            "\n\tUnsupported format for 'env_file', can be one of (.json, .yaml, .yml, .txt, .text, or null)"
        )


def load_env() -> EnvConfig:
    """Loads te env vars based on the env_file provided.

    See Also:
        This function allows env vars to be loaded partially from .env files and partially through kwargs.

    Returns:
        EnvConfig:
        Returns a reference to the ``EnvConfig`` object.
    """
    env_file = os.getenv("env_file") or os.getenv("ENV_FILE") or ".env"
    if os.path.isfile(env_file):
        return envfile_loader(env_file)
    # noinspection PyArgumentList
    return EnvConfig()


env: EnvConfig = load_env()
if env.enable_ui:
    assert (
        env.totp_token is not None
    ), "TOTP token must be provided if enable_ui is True"
    try:
        import pyotp  # noqa: F401
    except (ImportError, ModuleNotFoundError):  # pragma: no cover
        raise exceptions.StartupError(
            "Missing requirements. Please install 'vaultapi[ui]'"
        )
    validate_totp_secret(env.totp_token)
database: Database = Database(env.database)
session = Session()
