"""This is an entrypoint specific for docker containers."""

import json
import os
import pathlib
from datetime import datetime

logs_dir = os.path.join(pathlib.Path(__file__).parent, "logs")
db_file = os.environ.get("database") or os.environ.get("DATABASE") or "secrets.db"
db_path = os.path.join(pathlib.Path(__file__).parent, "data", db_file)

DEFAULT_LOG_FILENAME: str = datetime.now().strftime(
    os.path.join(logs_dir, "vaultapi_%d-%m-%Y.log")
)

os.makedirs(logs_dir, exist_ok=True)

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
os.environ["database"] = db_path

import vaultapi.server  # noqa: E402

if __name__ == "__main__":
    vaultapi.server.start()
