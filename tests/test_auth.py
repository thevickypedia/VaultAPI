"""Tests for vaultapi/auth.py — validate() function."""

import logging
import time
from unittest.mock import MagicMock

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from tests.conftest import _IN_MEMORY_AUTH_CONN
from vaultapi import auth, database, models
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


@pytest.mark.asyncio
class TestAuthValidate:
    async def test_forbidden_for_blocked_host(self):
        # Exceed the limit so the host is blocked
        for _ in range(database.FAILED_AUTH_LIMIT):
            database.increment_failed_auth("10.99.99.99")
        req = _make_request(host="10.99.99.99")
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("anything"))
        assert exc_info.value.status_code == 403
        assert "Blocked until" in exc_info.value.detail

    async def test_valid_api_key_accepted(self):
        from tests.conftest import API_KEY

        req = _make_request()
        await auth.validate(req, _make_creds(API_KEY))  # must not raise

    async def test_invalid_api_key_rejected(self):
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong-key"))
        assert exc_info.value.status_code == 401

    async def test_api_key_with_backslash_escape(self):
        r"""Credentials starting with \\ should be unicode-escape decoded."""
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("\\wrong"))
        assert exc_info.value.status_code == 401

    async def test_valid_ui_session_accepted(self):
        from tests.conftest import _set_valid_ui_session

        token = _set_valid_ui_session()
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        await auth.validate(req, _make_creds(token))  # must not raise

    async def test_invalid_ui_session_token_rejected(self):
        from tests.conftest import _set_valid_ui_session

        _set_valid_ui_session()
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong-token"))
        assert exc_info.value.status_code == 401

    async def test_expired_ui_session_rejected(self):
        """Session written with a past expiry must be rejected."""
        token = "expired-test-token"
        database.upsert_ui_session(
            token, "127.0.0.1", int(time.time()) - 1, models.session.fernet
        )
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token))
        assert exc_info.value.status_code == 401

    async def test_wrong_host_rejected(self):
        """Session written for host-A must be rejected when request comes from host-B."""
        token = "host-bound-token"
        database.upsert_ui_session(
            token, "192.168.1.100", int(time.time()) + 900, models.session.fernet
        )
        req = _make_request(host="127.0.0.1", headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token))
        assert exc_info.value.status_code == 401

    async def test_empty_ui_session_rejected(self):
        """No session in DB must fail."""
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(""))
        assert exc_info.value.status_code == 401

    async def test_user_agent_logged(self, caplog):
        from tests.conftest import API_KEY

        req = _make_request(headers={"user-agent": "pytest/1.0"})
        with caplog.at_level(logging.DEBUG, logger="uvicorn.default"):
            await auth.validate(req, _make_creds(API_KEY))

    async def test_failed_auth_increments_counter(self):
        req = _make_request(host="1.2.3.4")
        with pytest.raises(APIResponse):
            await auth.validate(req, _make_creds("wrong"))
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth, blocked_until FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("1.2.3.4",),
        ).fetchone()
        assert row is not None and row[0] == 1
        assert row[1] is None  # one failure — no cooloff yet

    async def test_successful_auth_resets_counter(self):
        from tests.conftest import API_KEY

        database.increment_failed_auth("127.0.0.1")
        req = _make_request(host="127.0.0.1")
        await auth.validate(req, _make_creds(API_KEY))
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
                await auth.validate(req, _make_creds("wrong"))
            assert exc_info.value.status_code == 401
        # Next attempt — host is now blocked
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("wrong"))
        assert exc_info.value.status_code == 403
        assert "Blocked until" in exc_info.value.detail
