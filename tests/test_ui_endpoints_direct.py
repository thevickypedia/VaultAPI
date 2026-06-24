"""Direct unit tests for UI endpoint handlers to cover auth-exception branches."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from tests.conftest import API_KEY
from vaultapi import database, exceptions, header, models, ui_endpoints


def _req(host="127.0.0.1", headers=None):
    req = MagicMock()
    req.url.hostname = host
    req.client.host = host
    req.headers = MagicMock()
    req.headers.get = lambda k, d="": (headers or {}).get(k, d)
    req.json = AsyncMock(return_value={})
    return req


def _creds(token="bad"):
    c = MagicMock(spec=HTTPAuthorizationCredentials)
    c.credentials = token
    return c


def _valid_api_creds():
    return _creds(header.generate(API_KEY))


@pytest.mark.asyncio
class TestUiAuthExceptBranches:
    """Handlers propagate APIResponse — use pytest.raises."""

    async def test_list_tables_auth_fail(self):
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_list_tables(_req(), _creds())
        assert exc.value.status_code == 401

    async def test_get_table_auth_fail(self):
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_get_table(_req(), "any_table", _creds())
        assert exc.value.status_code == 401

    async def test_create_table_auth_fail(self):
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_create_table(_req(), "any_table", _creds())
        assert exc.value.status_code == 401

    async def test_delete_table_auth_fail(self):
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_delete_table(_req(), "any_table", _creds())
        assert exc.value.status_code == 401

    async def test_put_secret_auth_fail(self):
        req = _req()
        req.json = AsyncMock(return_value={"table_name": "t", "key": "k", "value": "v"})
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_put_secret(req, _creds())
        assert exc.value.status_code == 401

    async def test_delete_secret_auth_fail(self):
        req = _req()
        req.json = AsyncMock(return_value={"table_name": "t", "key": "k"})
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_delete_secret(req, _creds())
        assert exc.value.status_code == 401

    async def test_import_secrets_auth_fail(self):
        req = _req()
        req.json = AsyncMock(
            return_value={
                "table_name": "t",
                "payload": '{"k":"v"}',
                "payload_type": "json",
            }
        )
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_import_secrets(req, _creds())
        assert exc.value.status_code == 401

    async def test_rename_table_auth_fail(self):
        req = _req()
        req.json = AsyncMock(return_value={"new_name": "newname"})
        with pytest.raises(exceptions.APIResponse) as exc:
            await ui_endpoints.ui_rename_table(req, "any_table", _creds())
        assert exc.value.status_code == 401


@pytest.mark.asyncio
class TestUiLoginNoTotp:
    """Cover the path when totp_token is None → validate_totp returns False → 401."""

    async def test_login_without_totp_returns_401(self):
        import pyotp

        from tests.conftest import TOTP_SECRET

        totp = pyotp.TOTP(TOTP_SECRET).now()
        req = _req(headers={"mfa-code": totp})
        with patch.object(models.env, "totp_token", None):
            with pytest.raises(exceptions.APIResponse) as exc:
                await ui_endpoints.ui_login(req, _valid_api_creds())
        assert exc.value.status_code == 401


@pytest.mark.asyncio
class TestUiDeleteTotpException:
    """Cover the TOTP exception path → validate_totp returns False → unauthorized() raises."""

    async def test_delete_table_totp_exception_raises_401(self):
        database.create_table("totp_exc_tbl", ["key", "value"])
        from tests.conftest import _set_valid_ui_session

        token = _set_valid_ui_session()
        req = _req(headers={"mfa-code": "123456"})
        req.json = AsyncMock(return_value={})
        creds = _creds(token)
        with patch("pyotp.TOTP") as mock_totp:
            mock_totp.return_value.verify.side_effect = Exception("otp boom")
            with pytest.raises(exceptions.APIResponse) as exc:
                await ui_endpoints.ui_delete_table(req, "totp_exc_tbl", creds)
        assert exc.value.status_code == 401

    async def test_delete_secret_totp_exception_raises_401(self):
        database.create_table("totp_exc_sec", ["key", "value"])
        from tests.conftest import _set_valid_ui_session

        token = _set_valid_ui_session()
        req = _req(headers={"mfa-code": "123456"})
        req.json = AsyncMock(return_value={"table_name": "totp_exc_sec", "key": "K"})
        creds = _creds(token)
        with patch("pyotp.TOTP") as mock_totp:
            mock_totp.return_value.verify.side_effect = Exception("otp boom")
            with pytest.raises(exceptions.APIResponse) as exc:
                await ui_endpoints.ui_delete_secret(req, creds)
        assert exc.value.status_code == 401


@pytest.mark.asyncio
class TestUiDeleteSecretRetrieveError:
    """Cover the retrieve_secret APIResponse propagation in ui_delete_secret."""

    async def test_retrieve_error_propagated(self):
        database.create_table("ds_rerr", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("ERR_K", encrypted, "ds_rerr")

        from tests.conftest import _set_valid_ui_session, make_totp

        token = _set_valid_ui_session()
        req = _req(headers={"mfa-code": make_totp()})
        req.json = AsyncMock(return_value={"table_name": "ds_rerr", "key": "ERR_K"})
        creds = _creds(token)

        with patch(
            "vaultapi.core.retrieve_secret",
            side_effect=exceptions.APIResponse(status_code=400, detail="db error"),
        ):
            with pytest.raises(exceptions.APIResponse) as exc:
                await ui_endpoints.ui_delete_secret(req, creds)
        assert exc.value.status_code == 400
