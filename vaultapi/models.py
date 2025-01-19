import json
import logging
import os
import pathlib
import re
import socket
import sqlite3
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

from . import ipaddress

LOGGER = logging.getLogger("uvicorn.default")
DEFAULT_ALLOWED = ["0.0.0.0", "127.0.0.1", "localhost"]


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
    allowed_origins: Set[str] = Field(default_factory=set)

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
    log_config: FilePath | Dict[str, Any] | None = None
    allow_public_ip: bool = False
    allow_private_ip: bool = False
    allow_private_ip_range: bool = False
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

    @field_validator("transit_key_length", mode="after", check_fields=True)
    def validate_transit_key_length(cls, value: PositiveInt) -> PositiveInt | NoReturn:
        """Validate transit key length."""
        if value in (16, 24, 32):
            return value
        raise ValueError("Transit key length (AES) must be one of 16, 24, or 32 bytes.")

    @field_validator("allowed_origins", mode="after", check_fields=True)
    def validate_allowed_origins(cls, value: HttpUrl | List[HttpUrl]) -> List[HttpUrl]:
        """Validate allowed origins to enable CORS policy."""
        if isinstance(value, list):
            return value
        return [value]

    @field_validator("allowed_ip_range", mode="after", check_fields=True)
    def validate_allowed_ip_range(cls, value: List[str]) -> List[str]:
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


def __init__() -> None:
    """Instantiates the env, session and database connections."""
    session.fernet = Fernet(env.secret)
    if env.host in DEFAULT_ALLOWED:
        session.allowed_origins.update(DEFAULT_ALLOWED)
    else:
        session.allowed_origins.add(env.host)
    for allowed in env.allowed_origins:
        session.allowed_origins.add(allowed.host)

    # Include private IP or private IP range to the allowed list
    if env.allow_private_ip or env.allow_private_ip_range:
        if private_ip := ipaddress.private():
            if env.allow_private_ip_range:
                network_id = ".".join(private_ip.split(".")[:3])
                dockerized_ip_range = f"{network_id}.1-256"
                LOGGER.warning("Allowing dockerized IP range: %s", dockerized_ip_range)
                env.allowed_ip_range.append(dockerized_ip_range)
            else:
                session.allowed_origins.add(private_ip)
        else:
            LOGGER.error("Failed to retrieve private IP address of the host machine")

    # Include public IP to the allowed list
    if env.allow_public_ip:
        if public_ip := ipaddress.public():
            session.allowed_origins.add(public_ip)
        else:
            LOGGER.error("Failed to retrieve public IP address of the host machine")

    for cidr_range in env.allowed_ip_range:
        ip_notion = ".".join(cidr_range.split(".")[0:-1])
        start_ip, end_ip = cidr_range.split(".")[-1].split("-")
        start_ip, end_ip = int(start_ip), int(end_ip) + 1
        for i in range(start_ip, end_ip):
            session.allowed_origins.add(f"{ip_notion}.{i}")


env: EnvConfig = load_env()
database: Database = Database(env.database)
session = Session()
__init__()
