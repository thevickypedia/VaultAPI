# VaultAPI
Lightweight API to store/retrieve secrets to/from an encrypted Database

![Python][label-pyversion]

**Platform Supported**

![Platform][label-platform]

**Deployments**

[![pages][label-actions-pages]][gha_pages]
[![pypi][label-actions-pypi]][gha_pypi]
[![markdown][label-actions-markdown]][gha_md_valid]

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

- **HOST** - Hostname for the API server.
- **PORT** - Port number for the API server.
- **WORKERS** - Number of workers for the uvicorn server.
- **APIKEY** - API Key for authentication.
- **SECRET** - Secret access key to encode/decode the secrets in Datastore.
- **DATABASE** - FilePath to store the secrets' database.
- **RATE_LIMIT** - List of dictionaries with `max_requests` and `seconds` to apply as rate limit.

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

## Runbook
[![made-with-sphinx-doc][label-sphinx-doc]][sphinx]

[https://thevickypedia.github.io/VaultAPI/][runbook]

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][license]

[label-actions-markdown]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yaml/badge.svg
[label-pypi-package]: https://img.shields.io/badge/Pypi%20Package-VaultAPI-blue?style=for-the-badge&logo=Python
[label-sphinx-doc]: https://img.shields.io/badge/Made%20with-Sphinx-blue?style=for-the-badge&logo=Sphinx
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
[release-notes]: https://github.com/thevickypedia/VaultAPI/blob/master/release_notes.rst
[gha_pages]: https://github.com/thevickypedia/VaultAPI/actions/workflows/pages/pages-build-deployment
[gha_pypi]: https://github.com/thevickypedia/VaultAPI/actions/workflows/python-publish.yaml
[gha_md_valid]: https://github.com/thevickypedia/VaultAPI/actions/workflows/markdown.yaml
[google-docs]: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
[pep8]: https://www.python.org/dev/peps/pep-0008/
[isort]: https://pycqa.github.io/isort/
[sphinx]: https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html
[pypi]: https://pypi.org/project/VaultAPI
[pypi-files]: https://pypi.org/project/VaultAPI/#files
[pypi-repo]: https://packaging.python.org/tutorials/packaging-projects/
[license]: https://github.com/thevickypedia/VaultAPI/blob/master/LICENSE
[runbook]: https://thevickypedia.github.io/VaultAPI/
