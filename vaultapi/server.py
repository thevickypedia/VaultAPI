import pathlib

import uvicorn


def start() -> None:
    """Starter function for the API, which uses uvicorn server as trigger."""
    from . import database, models

    database.create_table("default", ["key", "value"])
    module_name = pathlib.Path(__file__)
    kwargs = dict(
        host=models.env.host,
        port=models.env.port,
        workers=models.env.workers,
        app=f"{module_name.parent.stem}.api:VaultAPI",
    )
    if models.env.log_config:
        kwargs["log_config"] = models.env.log_config
    uvicorn.run(**kwargs)
