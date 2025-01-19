# VaultAPI
Lightweight API to store/retrieve secrets to/from an encrypted Database

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]
![docker-image][image-size]

**Deployments**

[![docker][label-docker-build]][gha_docker]
[![pypi][label-actions-pypi]][gha_pypi]
[![docker_desc][label-docker-desc]][gha_docker_desc]

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
import vaultapi.server


if __name__ == '__main__':
    vaultapi.server.start()
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
- **SECRET** - Secret access key to encode/decode the secrets in Datastore.

**Optional (with defaults)**
- **TRANSIT_KEY_LENGTH** - AES key length for transit encryption. Defaults to `32`
- **TRANSIT_TIME_BUCKET** - Interval for which the transit epoch should remain constant. Defaults to `60`
- **DATABASE** - FilePath to store the secrets' database. Defaults to `secrets.db`
- **HOST** - Hostname for the API server. Defaults to `0.0.0.0` [OR] `localhost`
- **PORT** - Port number for the API server. Defaults to `9010`
- **WORKERS** - Number of workers for the uvicorn server. Defaults to `1`
- **RATE_LIMIT** - List of dictionaries with `max_requests` and `seconds` to apply as rate limit.
Defaults to 5req/2s [AND] 10req/30s
- **ALLOW_PUBLIC_IP** - Boolean flag to allow connections via public IP. Defaults to `false`
- **ALLOW_PRIVATE_IP** - Boolean flag to allow connections via private IP. Defaults to `false`
- **ALLOW_PRIVATE_IP_RANGE** - Boolean flag to allow connections via any private IP address _(`1-256`)_ within range. Defaults to `false`

**Optional (without defaults)**
- **LOG_CONFIG** - FilePath or dictionary of key-value pairs for log config.
- **ALLOWED_ORIGINS** - Origins that are allowed to retrieve secrets.
- **ALLOWED_IP_RANGE** - IP range that is allowed to retrieve secrets. _(eg: `10.112.8.10-210`)_

> Checkout [decryptors][decryptors] for more information about decrypting the retrieved secret from the server.

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

[label-actions-markdown]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yaml/badge.svg
[label-docker-build]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker-publish.yaml/badge.svg
[label-docker-desc]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker-description.yaml/badge.svg
[label-pypi-package]: https://img.shields.io/badge/Pypi%20Package-VaultAPI-blue?style=for-the-badge&logo=Python
[label-sphinx-doc]: https://img.shields.io/badge/Made%20with-Sphinx-blue?style=for-the-badge&logo=Sphinx
[label-docker-doc]: https://img.shields.io/badge/Made%20with-Docker-blue?style=for-the-badge&logo=Docker
[label-pyversion]: https://img.shields.io/badge/python-3.10%20%7C%203.11-blue
[label-platform]: https://img.shields.io/badge/Platform-Linux|macOS|Windows-1f425f.svg
[label-actions-pages]: https://github.com/thevickypedia/VaultAPI/actions/workflows/pages/pages-build-deployment/badge.svg
[label-actions-pypi]: https://github.com/thevickypedia/VaultAPI/actions/workflows/python-publish.yaml/badge.svg
[label-pypi]: https://img.shields.io/pypi/v/VaultAPI
[label-pypi-format]: https://img.shields.io/pypi/format/VaultAPI
[label-pypi-status]: https://img.shields.io/pypi/status/VaultAPI

[3.10]: https://docs.python.org/3/whatsnew/3.10.html
[3.11]: https://docs.python.org/3/whatsnew/3.11.html
[virtual environment]: https://docs.python.org/3/tutorial/venv.html
[release-notes]: https://github.com/thevickypedia/VaultAPI/blob/main/release_notes.rst
[decryptors]: https://github.com/thevickypedia/VaultAPI/blob/main/decryptors
[gha_pages]: https://github.com/thevickypedia/VaultAPI/actions/workflows/pages/pages-build-deployment
[gha_docker]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker-publish.yaml
[gha_docker_desc]: https://github.com/thevickypedia/VaultAPI/actions/workflows/docker-description.yaml
[gha_pypi]: https://github.com/thevickypedia/VaultAPI/actions/workflows/python-publish.yaml
[gha_md_valid]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yaml
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
