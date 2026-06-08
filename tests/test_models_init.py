"""Tests for models.__init__() IP-lookup branches."""

from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from vaultapi import models
from vaultapi.models import EnvConfig, Session

VALID_KEY = "TestApiKey1!SecurePass#Word99@XYZ"
VALID_SECRET = Fernet.generate_key().decode()


def _run_init(env_overrides=None, private_ip=None, public_ip=None):
    """Run models.__init__() in isolation with patched IP lookups."""
    base_env = dict(
        apikey=VALID_KEY,
        secret=VALID_SECRET,
        **(env_overrides or {}),
    )
    test_env = EnvConfig(**base_env)
    test_session = Session()

    with (
        patch("vaultapi.models.env", test_env),
        patch("vaultapi.models.session", test_session),
        patch("vaultapi.ipaddress.private", return_value=private_ip),
        patch("vaultapi.ipaddress.public", return_value=public_ip),
    ):
        models.__init__()

    return test_session


class TestModelsInit:
    def test_default_origins_included(self):
        session = _run_init()
        assert "127.0.0.1" in session.allowed_origins

    def test_allow_private_ip_adds_to_origins(self):
        session = _run_init(
            env_overrides={"allow_private_ip": True},
            private_ip="192.168.1.100",
        )
        assert "192.168.1.100" in session.allowed_origins

    def test_allow_private_ip_none_does_not_add_origin(self):
        session = _run_init(env_overrides={"allow_private_ip": True}, private_ip=None)
        # No IP should have been added from a None result — just the defaults
        assert None not in session.allowed_origins

    def test_allow_private_ip_range_adds_range(self):
        session = _run_init(
            env_overrides={"allow_private_ip_range": True},
            private_ip="10.0.0.5",
        )
        # Range 10.0.0.1-256 should be expanded
        assert "10.0.0.1" in session.allowed_origins

    def test_allow_public_ip_adds_to_origins(self):
        session = _run_init(
            env_overrides={"allow_public_ip": True},
            public_ip="1.2.3.4",
        )
        assert "1.2.3.4" in session.allowed_origins

    def test_allow_public_ip_none_does_not_add_origin(self):
        session = _run_init(env_overrides={"allow_public_ip": True}, public_ip=None)
        assert None not in session.allowed_origins

    def test_ip_range_config_expanded(self):
        session = _run_init(
            env_overrides={"allowed_ip_range": ["192.168.1.10-12"]},
        )
        assert "192.168.1.10" in session.allowed_origins
        assert "192.168.1.11" in session.allowed_origins
        assert "192.168.1.12" in session.allowed_origins
        assert "192.168.1.13" not in session.allowed_origins

    def test_non_default_host_only_adds_itself(self):
        session = _run_init(env_overrides={"host": "10.1.2.3"})
        assert "10.1.2.3" in session.allowed_origins
        assert "127.0.0.1" not in session.allowed_origins
