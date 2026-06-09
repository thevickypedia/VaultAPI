"""Tests for vaultapi/auth.py — validate() function and JWT helpers."""

import base64
import hashlib
import hmac as _hmac
import json
import logging
from unittest.mock import MagicMock

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from vaultapi import auth
from vaultapi.exceptions import APIResponse


def _make_request(host: str = "127.0.0.1", headers: dict = None):
    req = MagicMock()
    req.url.hostname = host
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
        r"""Credentials starting with \\ should be unicode-escape decoded."""
        req = _make_request()
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("\\wrong"))
        assert exc_info.value.status_code == 401

    async def test_valid_ui_session_accepted(self):
        token = auth.create_ui_token("127.0.0.1")
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        await auth.validate(req, _make_creds(token))  # must not raise

    async def test_invalid_ui_session_token_rejected(self):
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds("not.a.jwt"))
        assert exc_info.value.status_code == 401

    async def test_expired_ui_session_rejected(self):
        token = auth.create_ui_token("127.0.0.1", lifetime=-1)
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token))
        assert exc_info.value.status_code == 401

    async def test_wrong_hostname_rejected(self):
        """JWT issued for host-A must be rejected when presented from host-B."""
        token = auth.create_ui_token("192.168.1.100")
        req = _make_request(host="127.0.0.1", headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(token))
        assert exc_info.value.status_code == 401

    async def test_empty_ui_session_rejected(self):
        req = _make_request(headers={"authenticator": "VaultAPI-UI"})
        with pytest.raises(APIResponse) as exc_info:
            await auth.validate(req, _make_creds(""))
        assert exc_info.value.status_code == 401

    async def test_user_agent_logged(self, caplog):
        from tests.conftest import API_KEY

        req = _make_request(headers={"user-agent": "pytest/1.0"})
        with caplog.at_level(logging.DEBUG, logger="uvicorn.default"):
            await auth.validate(req, _make_creds(API_KEY))


class TestCreateAndVerifyUiToken:
    def test_valid_token_verifies(self):
        token = auth.create_ui_token("myhost")
        assert auth.verify_ui_token(token, "myhost") is True

    def test_wrong_host_fails(self):
        token = auth.create_ui_token("host-a")
        assert auth.verify_ui_token(token, "host-b") is False

    def test_expired_token_fails(self):
        token = auth.create_ui_token("myhost", lifetime=-1)
        assert auth.verify_ui_token(token, "myhost") is False

    def test_tampered_payload_fails(self):
        token = auth.create_ui_token("myhost")
        header, payload, sig = token.split(".")
        # flip one char in payload
        tampered = payload[:-1] + ("A" if payload[-1] != "A" else "B")
        assert auth.verify_ui_token(f"{header}.{tampered}.{sig}", "myhost") is False

    def test_tampered_signature_fails(self):
        token = auth.create_ui_token("myhost")
        header, payload, sig = token.split(".")
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        assert auth.verify_ui_token(f"{header}.{payload}.{bad_sig}", "myhost") is False

    def test_wrong_part_count_fails(self):
        assert auth.verify_ui_token("only.two", "myhost") is False

    def test_garbage_token_fails(self):
        assert auth.verify_ui_token("garbage", "myhost") is False

    def test_multiple_tokens_are_independent(self):
        """Two tokens issued for the same host are distinct (jti) and both valid."""
        t1 = auth.create_ui_token("myhost")
        t2 = auth.create_ui_token("myhost")
        assert t1 != t2
        assert auth.verify_ui_token(t1, "myhost")
        assert auth.verify_ui_token(t2, "myhost")

    def test_custom_lifetime_respected(self):
        token = auth.create_ui_token("myhost", lifetime=3600)
        payload_b64 = token.split(".")[1]
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += "=" * (4 - rem)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        assert claims["exp"] - claims["iat"] == 3600

    def test_wrong_sub_claim_fails(self):
        """A JWT with a tampered sub claim must be rejected."""
        token = auth.create_ui_token("myhost")
        header_b64, payload_b64, _ = token.split(".")
        rem = len(payload_b64) % 4
        padded = payload_b64 + ("=" * ((4 - rem) % 4))
        claims = json.loads(base64.urlsafe_b64decode(padded))
        claims["sub"] = "evil"
        new_payload = auth._b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{new_payload}".encode()
        new_sig = auth._b64url(
            _hmac.new(auth._signing_key(), signing_input, hashlib.sha256).digest()
        )
        assert (
            auth.verify_ui_token(f"{header_b64}.{new_payload}.{new_sig}", "myhost")
            is False
        )

    def test_malformed_base64_payload_fails(self):
        """Non-JSON payload bytes must not raise — just return False."""
        assert auth.verify_ui_token("aGVhZGVy.!!!.c2ln", "myhost") is False

    def test_valid_signature_invalid_json_payload_falls_into_except(self):
        """Correctly-signed token with non-JSON payload hits the except block."""
        header = auth._b64url(b'{"alg":"HS256","typ":"JWT"}')
        payload = auth._b64url(b"not-valid-json")
        signing_input = f"{header}.{payload}".encode()
        sig = auth._b64url(
            _hmac.new(auth._signing_key(), signing_input, hashlib.sha256).digest()
        )
        assert auth.verify_ui_token(f"{header}.{payload}.{sig}", "myhost") is False
