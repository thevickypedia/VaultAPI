# VaultAPI
Lightweight API to store/retrieve secrets to/from an encrypted Database

VaultAPI is designed to be extremely lightweight, secure, and easy to use.
It provides cutting-edge security features like AES-GCM, Fernet encryption, and rate limiting all out of the box.
It also includes transit encryption to ensure that the secrets are encrypted during transit to protect against
man-in-the-middle attacks.

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]
![docker-image][image-size]

**Deployments**

[![docker][label-docker]][gha_docker]
[![pypi][label-actions-pypi]][gha_pypi]

[![coverage][label-coverage]][gha_coverage]
[![dependabot][label-dependabot]][gha_dependabot]

[![markdown][label-actions-markdown]][gha_md_valid]
[![pages][label-actions-pages]][gha_pages]

[![Pypi][label-pypi]][pypi]
[![Pypi-format][label-pypi-format]][pypi-files]
[![Pypi-status][label-pypi-status]][pypi]

## Kick off

**Recommendations**

- Install `python` [3.10] or [3.11]
- Use a dedicated [virtual environment]

**Install VaultAPI**
```shell
python -m pip install vaultapi
```

**Initiate - IDE**
```python
import vaultapi

if __name__ == '__main__':
    vaultapi.start()
```

**Initiate - CLI**
```shell
vaultapi start
```

> Use `vaultapi --help` for usage instructions.

## Environment Variables

<details>
<summary><strong>Sourcing environment variables from an env file</strong></summary>

> _By default, `VaultAPI` will look for a `.env` file in the current working directory._
</details>

**Mandatory**
- **APIKEY** - API Key for authentication.
- **SECRET** - Secret access key to encrypt/decrypt the secrets in the Datastore.

**Optional (with defaults)**
- **TRANSIT_KEY_LENGTH** - AES key length for transit encryption. Defaults to `32`
- **TRANSIT_TIME_BUCKET** - Interval for which the transit epoch should remain constant. Defaults to `60`
- **DATABASE** - FilePath to store the secrets' database. Defaults to `secrets.db`
- **HOST** - Hostname for the API server. Defaults to `0.0.0.0` [OR] `localhost`
- **PORT** - Port number for the API server. Defaults to `9010`
- **WORKERS** - Number of workers for the uvicorn server. Defaults to `1`
- **RATE_LIMIT** - List of dictionaries with `max_requests` and `seconds` to apply as rate limit.
  Defaults to 5req/2s [AND] 10req/30s

**Optional (without defaults)**
- **LOG_CONFIG** - FilePath or dictionary of key-value pairs for log config.
- **ALLOWED_ORIGINS** - List of origins that should be allowed through CORS.

**Optional (UI integration)**
- **ENABLE_UI** - Boolean flag to enable the UI. Defaults to `false`
- **AUTH_DATABASE** - FilePath to store the UI authentication database. Defaults to `auth.db`
- **TOTP_TOKEN** - Secret token for TOTP authentication in the UI. Can be generated using any TOTP generator app like
  `Google Authenticator` or `Authy`.
- **UI_LIFETIME** - Time in seconds for which the UI session should remain active. Defaults to `900` (15 minutes)

<details>
<summary>Auto generate a <code>SECRET</code> value</summary>

This value will be used to encrypt/decrypt the secrets stored in the database.

**CLI**
```shell
vaultapi keygen
```

**IDE**
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key())
```
</details>

## API Functionality

| Endpoint         | Description                                | API method | Authorization Header                 |
|------------------|--------------------------------------------|------------|--------------------------------------|
| `/health`        | API health endpoint                        | GET        | N/A                                  |
| `/get-secret`    | Retrieve secrets (comma separated list)    | GET        | HMAC-SHA512(apikey+timestamp)        |
| `/get-table`     | Get ALL the secrets stored in a table      | GET        | HMAC-SHA512(apikey+timestamp)        |
| `/list-tables`   | List all available tables                  | GET        | HMAC-SHA512(apikey+timestamp)        |
| `/create-table`  | Create a new table                         | POST       | HMAC-SHA512(apikey+timestamp)        |
| `/put-secret`    | Store or update a secret (key-value pairs) | PUT        | HMAC-SHA512(apikey+secret+timestamp) |
| `/delete-secret` | Delete a specific secret                   | DELETE     | HMAC-SHA512(apikey+secret+timestamp) |
| `/delete-table`  | Deletes an existing table                  | DELETE     | HMAC-SHA512(apikey+secret+timestamp) |
| `/rename-table`  | Renames an existing table                  | PATCH      | HMAC-SHA512(apikey+secret+timestamp) |

## Clients
Clients are available in multiple languages to interact with the API server.

**Python**: [VaultAPI-Client-python]

**Rust**: [VaultAPI-Client-rust]

> Checkout [decryptors][decryptors] for on-demand scripts to decrypt the secrets retrieved from the API.

## Coding Standards
Docstring format: [`Google`][google-docs] <br>
Styling conventions: [`PEP 8`][pep8] and [`isort`][isort]

## [Release Notes][release-notes]
**Requirement**
```shell
python -m pip install gitverse
```

**Usage**
```shell
gitverse-release reverse -f release_notes.rst -t 'Release Notes'
```

## Linting
`pre-commit` will ensure linting, run pytest, generate runbook & release notes, and validate hyperlinks in ALL
markdown files (including Wiki pages)

**Requirement**
```shell
python -m pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

## Pypi Package
[![pypi-module][label-pypi-package]][pypi-repo]

[https://pypi.org/project/VaultAPI/][pypi]

## Docker Image
[![made-with-docker-doc][label-docker-doc]][docker-doc]

[https://hub.docker.com/r/thevickypedia/vaultapi][docker]

## Runbook
[![made-with-sphinx-doc][label-sphinx-doc]][sphinx]

[https://thevickypedia.github.io/VaultAPI/][runbook]

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][license]

[VaultAPI-Client-python]: https://github.com/thevickypedia/VaultAPI-Client-python
[VaultAPI-Client-rust]: https://github.com/thevickypedia/VaultAPI-Client-rust
[label-actions-markdown]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yml/badge.svg
[label-dependabot]: https://github.com/thevickypedia/VaultAPI/actions/workflows/dependabot/update-graph/badge.svg
[label-coverage]: https://github.com/thevickypedia/VaultAPI/actions/workflows/code-coverage.yml/badge.svg
[label-docker]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker.yml/badge.svg
[label-pypi-package]: https://img.shields.io/badge/Pypi%20Package-VaultAPI-blue?style=for-the-badge&logo=Python
[label-sphinx-doc]: https://img.shields.io/badge/Made%20with-Sphinx-blue?style=for-the-badge&logo=Sphinx
[label-docker-doc]: https://img.shields.io/badge/Made%20with-Docker-blue?style=for-the-badge&logo=Docker
[label-pyversion]: https://img.shields.io/badge/python-3.10%20%7C%203.11-blue
[label-platform]: https://img.shields.io/badge/Platform-Linux|macOS|Windows-1f425f.svg
[label-actions-pages]: https://github.com/thevickypedia/VaultAPI/actions/workflows/pages/pages-build-deployment/badge.svg
[label-actions-pypi]: https://github.com/thevickypedia/VaultAPI/actions/workflows/python-publish.yml/badge.svg
[label-pypi]: https://img.shields.io/pypi/v/VaultAPI
[label-pypi-format]: https://img.shields.io/pypi/format/VaultAPI
[label-pypi-status]: https://img.shields.io/pypi/status/VaultAPI

[3.10]: https://docs.python.org/3/whatsnew/3.10.html
[3.11]: https://docs.python.org/3/whatsnew/3.11.html
[virtual environment]: https://docs.python.org/3/tutorial/venv.html
[release-notes]: https://github.com/thevickypedia/VaultAPI/blob/main/release_notes.rst
[decryptors]: https://github.com/thevickypedia/VaultAPI/blob/main/decryptors
[gha_pages]: https://github.com/thevickypedia/VaultAPI/actions/workflows/pages/pages-build-deployment
[gha_coverage]: https://github.com/thevickypedia/VaultAPI/actions/workflows/code-coverage.yml
[gha_dependabot]: https://github.com/thevickypedia/VaultAPI/actions/workflows/dependabot/update-graph
[gha_docker]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker.yml
[gha_pypi]: https://github.com/thevickypedia/VaultAPI/actions/workflows/python-publish.yml
[gha_md_valid]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yml
[google-docs]: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
[pep8]: https://www.python.org/dev/peps/pep-0008/
[isort]: https://pycqa.github.io/isort/
[docker]: https://hub.docker.com/r/thevickypedia/vaultapi
[docker-doc]: https://docs.docker.com/
[sphinx]: https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html
[image-size]: https://img.shields.io/docker/image-size/thevickypedia/vaultapi/latest
[pypi]: https://pypi.org/project/VaultAPI
[pypi-files]: https://pypi.org/project/VaultAPI/#files
[pypi-repo]: https://packaging.python.org/tutorials/packaging-projects/
[license]: https://github.com/thevickypedia/VaultAPI/blob/main/LICENSE
[runbook]: https://thevickypedia.github.io/VaultAPI/
