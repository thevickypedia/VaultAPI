"""This is an entrypoint specific for docker containers."""

import json
import os
import pathlib
from datetime import datetime

import vaultapi

db_filename = lambda key, default: os.environ.get(key) or os.environ.get(key.upper()) or default  # noqa: E731
logs_dir = pathlib.Path(__file__).parent / "logs"
data_dir = pathlib.Path(__file__).parent / "data"
db_path = data_dir / db_filename("database", "secrets.db")
auth_db = data_dir / db_filename("auth_database", "auth.db")

DEFAULT_LOG_FILENAME: str = datetime.now().strftime(str(logs_dir / "vaultapi_%d-%m-%Y.log"))
data_dir.mkdir(parents=True, exist_ok=True)
logs_dir.mkdir(parents=True, exist_ok=True)

log_config = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(asctime)s %(levelprefix)-9s %(name)s -: %(message)s",
            "use_colors": False,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(asctime)s %(levelprefix)-9s %(name)s -: %(client_addr)s - "%(request_line)s" %(status_code)s',
            "use_colors": False,
        },
        "error": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(asctime)s %(levelprefix)-9s %(name)s -: %(message)s",
            "use_colors": False,
        },
    },
    "handlers": {
        "default": {
            "class": "logging.FileHandler",
            "formatter": "default",
            "filename": DEFAULT_LOG_FILENAME,
        },
        "access": {
            "class": "logging.FileHandler",
            "formatter": "access",
            "filename": DEFAULT_LOG_FILENAME,
        },
        "error": {
            "class": "logging.FileHandler",
            "formatter": "error",
            "filename": DEFAULT_LOG_FILENAME,
        },
    },
    "loggers": {
        "uvicorn": {"propagate": True, "level": "INFO", "handlers": ["default"]},
        "uvicorn.error": {"propagate": True, "level": "INFO", "handlers": ["error"]},
        "uvicorn.access": {"propagate": True, "level": "INFO", "handlers": ["access"]},
    },
}

os.environ["log_config"] = json.dumps(log_config)
os.environ["database"] = str(db_path)
os.environ["auth_database"] = str(auth_db)


if __name__ == "__main__":
    vaultapi.start()
