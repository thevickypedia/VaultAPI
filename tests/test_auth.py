"""Tests for vaultapi/auth.py — validate() function."""

import logging
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from tests.conftest import _IN_MEMORY_AUTH_CONN, API_KEY, FERNET_KEY
from vaultapi import auth, database, header, models
from vaultapi.exceptions import APIResponse


def _make_request(host: str = "127.0.0.1", headers: dict = None):
    req = MagicMock()
    req.url.hostname = host
    req.client.host = host
    req.headers = MagicMock()
    req.headers.get = lambda key, default="": (headers or {}).get(key, default)
    return req


def _make_creds(token: str) -> HTTPAuthorizationCredentials:
    creds = MagicMock(spec=HTTPAuthorizationCredentials)
    creds.credentials = token
    return creds


def _hmac_creds(token: str = None) -> HTTPAuthorizationCredentials:
    """Return credentials using a fresh HMAC signature for the given token."""
    t = token if token is not None else API_KEY
    return _make_creds(header.generate(t))


@pytest.mark.asyncio
class TestAuthValidate:
    async def test_forbidden_for_blocked_host(self):
        for _ in range(database.FAILED_AUTH_LIMIT):
            database.increment_failed_auth("10.99.99.99")
        req = _make_request(host="10.99.99.99")
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("anything"), auth_type=auth.AuthType.api_basic)
        assert exc_info.value.status_code == 403
        assert "Blocked until" in exc_info.value.detail

    async def test_valid_api_key_accepted(self):
        req = _make_request()
        await auth.validate(req, _hmac_creds(API_KEY), auth_type=auth.AuthType.api_basic)

    async def test_invalid_api_key_rejected(self):
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong-key"), auth_type=auth.AuthType.api_basic)
        assert exc_info.value.status_code == 401

    async def test_api_key_with_backslash_escape(self):
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("\\wrong"), auth_type=auth.AuthType.api_basic)
        assert exc_info.value.status_code == 401

    async def test_valid_api_advanced_accepted(self):
        req = _make_request()
        await auth.validate(
            req,
            _hmac_creds(f"{API_KEY}.{FERNET_KEY}"),
            auth_type=auth.AuthType.api_advanced,
        )

    async def test_invalid_api_advanced_rejected(self):
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong-key"), auth_type=auth.AuthType.api_advanced)
        assert exc_info.value.status_code == 401

    async def test_valid_ui_login_accepted(self):
        import pyotp

        from tests.conftest import TOTP_SECRET

        totp = pyotp.TOTP(TOTP_SECRET).now()
        req = _make_request(headers={"mfa-code": totp})
        await auth.validate(req, _hmac_creds(API_KEY), auth_type=auth.AuthType.ui_login)

    async def test_ui_login_wrong_totp_rejected(self):
        req = _make_request(headers={"mfa-code": "000000"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _hmac_creds(API_KEY), auth_type=auth.AuthType.ui_login)
        assert exc_info.value.status_code == 401

    async def test_ui_login_wrong_apikey_rejected(self):
        req = _make_request(headers={"mfa-code": "000000"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("bad"), auth_type=auth.AuthType.ui_login)
        assert exc_info.value.status_code == 401

    async def test_valid_ui_session_accepted(self):
        from tests.conftest import _set_valid_ui_session

        token = _set_valid_ui_session()
        req = _make_request()
        await auth.validate(req, _make_creds(token), auth_type=auth.AuthType.ui_basic)

    async def test_invalid_ui_session_token_rejected(self):
        from tests.conftest import _set_valid_ui_session

        _set_valid_ui_session()
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong-token"), auth_type=auth.AuthType.ui_basic)
        assert exc_info.value.status_code == 401

    async def test_expired_ui_session_rejected(self):
        token = "expired-test-token"
        database.upsert_ui_session(token, "127.0.0.1", int(time.time()) - 1, models.session.fernet)
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token), auth_type=auth.AuthType.ui_basic)
        assert exc_info.value.status_code == 401

    async def test_wrong_host_rejected(self):
        token = "host-bound-token"
        database.upsert_ui_session(token, "192.168.1.100", int(time.time()) + 900, models.session.fernet)
        req = _make_request(host="127.0.0.1")
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token), auth_type=auth.AuthType.ui_basic)
        assert exc_info.value.status_code == 401

    async def test_empty_ui_session_rejected(self):
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(""), auth_type=auth.AuthType.ui_basic)
        assert exc_info.value.status_code == 401

    async def test_valid_ui_advanced_accepted(self):
        import pyotp

        from tests.conftest import TOTP_SECRET, _set_valid_ui_session

        token = _set_valid_ui_session()
        totp = pyotp.TOTP(TOTP_SECRET).now()
        req = _make_request(headers={"mfa-code": totp})
        await auth.validate(req, _make_creds(token), auth_type=auth.AuthType.ui_advanced)

    async def test_ui_advanced_wrong_totp_rejected(self):
        from tests.conftest import _set_valid_ui_session

        token = _set_valid_ui_session()
        req = _make_request(headers={"mfa-code": "000000"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token), auth_type=auth.AuthType.ui_advanced)
        assert exc_info.value.status_code == 401

    async def test_user_agent_logged(self, caplog):
        req = _make_request(headers={"user-agent": "pytest/1.0"})
        with caplog.at_level(logging.DEBUG, logger="uvicorn.default"):
            await auth.validate(req, _hmac_creds(API_KEY), auth_type=auth.AuthType.api_basic)

    async def test_failed_auth_increments_counter(self):
        req = _make_request(host="1.2.3.4")
        with pytest.raises(APIResponse):
            await auth.validate(req, _make_creds("wrong"), auth_type=auth.AuthType.api_basic)
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth, blocked_until FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("1.2.3.4",),
        ).fetchone()
        assert row is not None and row[0] == 1
        assert row[1] is None

    async def test_successful_auth_resets_counter(self):
        database.increment_failed_auth("127.0.0.1")
        req = _make_request(host="127.0.0.1")
        await auth.validate(req, _hmac_creds(API_KEY), auth_type=auth.AuthType.api_basic)
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("127.0.0.1",),
        ).fetchone()
        assert row is not None and row[0] == 0

    async def test_blocked_after_limit_failures(self):
        host = "9.9.9.9"
        req = _make_request(host=host)
        for _ in range(database.FAILED_AUTH_LIMIT):
            with pytest.raises(APIResponse) as exc_info:
                await auth.validate(req, _make_creds("wrong"), auth_type=auth.AuthType.api_basic)
            assert exc_info.value.status_code == 401
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong"), auth_type=auth.AuthType.api_basic)
        assert exc_info.value.status_code == 403
        assert "Blocked until" in exc_info.value.detail


@pytest.mark.asyncio
class TestValidateTotp:
    async def test_valid_totp_returns_true(self):
        import pyotp

        from tests.conftest import TOTP_SECRET

        code = pyotp.TOTP(TOTP_SECRET).now()
        result = await auth.validate_totp(code)
        assert result is True

    async def test_invalid_totp_returns_false(self):
        result = await auth.validate_totp("000000")
        assert result is False

    async def test_totp_exception_returns_false(self):
        with patch("pyotp.TOTP.verify", side_effect=Exception("boom")):
            result = await auth.validate_totp("123456")
        assert result is False

    async def test_no_totp_token_configured_returns_false(self):
        with patch.object(models.env, "totp_token", None):
            result = await auth.validate_totp("123456")
        assert result is False
