import os
import sys

import click
from cryptography.fernet import Fernet

from . import version


@click.command()
@click.argument("run", required=False)
@click.argument("start", required=False)
@click.argument("keygen", required=False)
@click.option("--version", "-V", is_flag=True, help="Prints the version.")
@click.option("--help", "-H", is_flag=True, help="Prints the help section.")
@click.option(
    "--env",
    "-E",
    type=click.Path(exists=True),
    help="Environment configuration filepath.",
)
def commandline(*args, **kwargs) -> None:
    """Starter function to invoke VaultAPI via CLI commands.

    **Flags**
        - ``--version | -V``: Prints the version.
        - ``--help | -H``: Prints the help section.
        - ``--env | -E``: Environment configuration filepath.
    """
    assert sys.argv[0].lower().endswith("vaultapi"), "Invalid commandline trigger!!"
    options = {
        "--version | -V": "Prints the version.",
        "--help | -H": "Prints the help section.",
        "--env | -E": "Environment configuration filepath.",
        "start | run": "Initiates the API server.",
    }
    # weird way to increase spacing to keep all values monotonic
    _longest_key = len(max(options.keys()))
    _pretext = "\n\t* "
    choices = _pretext + _pretext.join(
        f"{k} {'·' * (_longest_key - len(k) + 8)}→ {v}".expandtabs()
        for k, v in options.items()
    )
    if kwargs.get("help"):
        click.echo(
            f"\nUsage: vaultapi [arbitrary-command]\nOptions (and corresponding behavior):{choices}"
        )
        sys.exit(0)
    if kwargs.get("version"):
        click.secho(f"VaultAPI v{version.__version__}", fg="green")
        sys.exit(0)

    # Store 'env' key's value as the env var 'env_file' - with default to '.env'
    os.environ["env_file"] = kwargs.get("env") or ".env"
    from .server import start

    trigger = (
        kwargs.get("start") or kwargs.get("run") or kwargs.get("keygen") or ""
    ).lower()
    if trigger in ("start", "run"):
        start()
        sys.exit(0)
    elif trigger == "keygen":
        key = Fernet.generate_key()
        click.secho(
            "\nStore this as an env var named 'secret' or the choice of env_file\n"
            "This secret will be required to decrypt the secrets retrieved from the API\n",
            fg="green",
        )
        click.secho(key.decode() + "\n", bold=True)
        sys.exit(0)
    else:
        click.secho(f"\n{kwargs}\nNo command provided", fg="red")
    click.echo(
        f"Usage: vaultapi [arbitrary-command]\nOptions (and corresponding behavior):{choices}"
    )
    sys.exit(1)
