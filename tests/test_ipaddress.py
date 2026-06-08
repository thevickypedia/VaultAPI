"""Tests for vaultapi/ipaddress.py — private() and public()."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from vaultapi.ipaddress import IP_REGEX, private, public


class TestIpRegex:
    def test_valid_ipv4(self):
        assert IP_REGEX.match("192.168.1.1")
        assert IP_REGEX.match("10.0.0.1")
        assert IP_REGEX.match("255.255.255.255")

    def test_invalid_cases(self):
        assert not IP_REGEX.match("256.0.0.1")
        assert not IP_REGEX.match("not.an.ip")
        assert not IP_REGEX.match("192.168.1")


class TestPrivateIp:
    def test_returns_string_on_success(self):
        result = private()
        # On a normal machine this should succeed and return an IP string
        if result is not None:
            assert IP_REGEX.match(result)

    def test_returns_none_on_os_error(self):
        with patch("socket.socket") as mock_sock_cls:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.connect.side_effect = OSError("network unreachable")
            mock_sock_cls.return_value = ctx
            assert private() is None


class TestPublicIp:
    def test_returns_none_when_all_fail(self):
        import requests as req_lib

        with patch.object(req_lib, "get", side_effect=req_lib.RequestException):
            result = public()
            assert result is None

    def test_returns_ip_from_first_endpoint(self):
        import requests as req_lib

        mock_response = MagicMock()
        mock_response.text = "1.2.3.4\n"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        with patch.object(req_lib, "get", return_value=mock_response):
            result = public()
            assert result == "1.2.3.4"

    def test_skips_bad_response_and_tries_next(self):
        import requests as req_lib

        def _make_bad():
            bad = MagicMock()
            bad.text = "not-an-ip"
            bad.json.return_value = {"origin": "not-an-ip"}
            bad.__enter__ = MagicMock(return_value=bad)
            bad.__exit__ = MagicMock(return_value=False)
            return bad

        good = MagicMock()
        good.text = "8.8.8.8"
        good.json.return_value = {"origin": "8.8.8.8"}
        good.__enter__ = MagicMock(return_value=good)
        good.__exit__ = MagicMock(return_value=False)

        side_effects = [_make_bad() for _ in range(5)] + [good]
        with patch.object(req_lib, "get", side_effect=side_effects):
            result = public()
            assert result == "8.8.8.8"
