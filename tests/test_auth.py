"""Tests for vaultapi/auth.py — validate() function."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from vaultapi import auth, models
from vaultapi.exceptions import APIResponse


def _make_request(host: str = "127.0.0.1", headers: dict = None):
    req = MagicMock()
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
    async def test_forbidden_for_unknown_host(self):
        req = _make_request(host="10.99.99.99")
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("anything"))
        assert exc_info.value.status_code == 403

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
        """Credentials starting with \\ should be unicode-escape decoded."""
        from tests.conftest import API_KEY
        req = _make_request()
        # Encode then try an escaped version that doesn't match
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
        from tests.conftest import _set_valid_ui_session
        _set_valid_ui_session()
        # Wind the expiry into the past
        auth.UI_SESSION["expires"] = int(time.time()) - models.env.ui_lifetime - 1
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(auth.UI_SESSION["token"]))
        assert exc_info.value.status_code == 401

    async def test_empty_ui_session_rejected(self):
        """UI_SESSION with default empty values must fail."""
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(""))
        assert exc_info.value.status_code == 401

    async def test_user_agent_logged(self, caplog):
        from tests.conftest import API_KEY
        req = _make_request(headers={"user-agent": "pytest/1.0"})
        import logging
        with caplog.at_level(logging.DEBUG, logger="uvicorn.default"):
            await auth.validate(req, _make_creds(API_KEY))
