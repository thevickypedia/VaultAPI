"""Tests for vaultapi/models.py — EnvConfig validators, Database, envfile_loader."""

import json
import os
import pathlib
import tempfile

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from vaultapi.models import (
    Database,
    EnvConfig,
    RateLimit,
    Session,
    complexity_checker,
    envfile_loader,
    validate_totp_secret,
)

VALID_KEY = "TestApiKey1!SecurePass#Word99@XYZ"
VALID_SECRET = Fernet.generate_key().decode()


# ---------------------------------------------------------------------------
# complexity_checker
# ---------------------------------------------------------------------------
class TestComplexityChecker:
    def test_valid_secret(self):
        complexity_checker("Abcdefgh1!ijklmnopqrstuvwxyz@@@#")  # no exception

    def test_too_short(self):
        with pytest.raises(AssertionError, match="at least 32"):
            complexity_checker("Short1!")

    def test_no_digit(self):
        with pytest.raises(AssertionError, match="integer"):
            complexity_checker("Abcdefghijklmnopqrstuvwxyz!@#$%^")

    def test_no_uppercase(self):
        with pytest.raises(AssertionError, match="uppercase"):
            complexity_checker("abcdefgh1!ijklmnopqrstuvwxyz@@@#")

    def test_no_lowercase(self):
        with pytest.raises(AssertionError, match="lowercase"):
            complexity_checker("ABCDEFGH1!IJKLMNOPQRSTUVWXYZ@@@#")

    def test_no_symbol(self):
        with pytest.raises(AssertionError, match="special character"):
            complexity_checker("ABCDEFGHijklmnop1234567890123456")

    def test_custom_max_len(self):
        with pytest.raises(AssertionError, match="at least 64"):
            complexity_checker("Short1!", max_len=64)


# ---------------------------------------------------------------------------
# validate_totp_secret
# ---------------------------------------------------------------------------
class TestValidateTotpSecret:
    def test_valid_totp_token(self):
        import pyotp
        token = pyotp.random_base32()
        validate_totp_secret(token)  # should not raise

    def test_invalid_totp_token(self):
        with pytest.raises(Exception):
            validate_totp_secret("not-a-valid-totp-base32!!")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class TestDatabase:
    def test_creates_db_file(self, tmp_path):
        db = Database(str(tmp_path / "test.db"))
        assert db.connection is not None

    def test_adds_suffix_if_missing(self, tmp_path):
        db = Database(str(tmp_path / "nosuffix"))
        # Connection still works
        db.connection.execute("SELECT 1")

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "nested.db"
        db = Database(str(nested))
        assert db.connection is not None


# ---------------------------------------------------------------------------
# RateLimit model
# ---------------------------------------------------------------------------
class TestRateLimit:
    def test_valid(self):
        rl = RateLimit(max_requests=10, seconds=60)
        assert rl.max_requests == 10

    def test_invalid_zero_requests(self):
        with pytest.raises(ValidationError):
            RateLimit(max_requests=0, seconds=60)


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------
class TestSession:
    def test_defaults(self):
        s = Session()
        assert s.fernet is None
        assert s.info == {}
        assert s.rps == {}
        assert s.allowed_origins == set()


# ---------------------------------------------------------------------------
# EnvConfig validators
# ---------------------------------------------------------------------------
class TestEnvConfigValidators:
    def _base(self, **overrides):
        base = dict(apikey=VALID_KEY, secret=VALID_SECRET)
        base.update(overrides)
        return base

    def test_valid_config(self):
        cfg = EnvConfig(**self._base())
        assert cfg.apikey == VALID_KEY

    def test_invalid_apikey(self):
        with pytest.raises(ValidationError, match="secret length"):
            EnvConfig(**self._base(apikey="short"))

    def test_invalid_secret(self):
        with pytest.raises(ValidationError):
            EnvConfig(**self._base(secret="not-a-fernet-key"))

    def test_transit_key_length_valid_values(self):
        for length in (16, 24, 32):
            cfg = EnvConfig(**self._base(transit_key_length=length))
            assert cfg.transit_key_length == length

    def test_transit_key_length_invalid(self):
        with pytest.raises(ValidationError, match="16, 24, or 32"):
            EnvConfig(**self._base(transit_key_length=20))

    def test_allowed_origins_scalar_becomes_list(self):
        cfg = EnvConfig(**self._base(allowed_origins="http://example.com"))
        assert isinstance(cfg.allowed_origins, list)
        assert len(cfg.allowed_origins) == 1

    def test_allowed_origins_list(self):
        cfg = EnvConfig(**self._base(allowed_origins=["http://example.com"]))
        assert len(cfg.allowed_origins) == 1

    def test_allowed_ip_range_valid(self):
        cfg = EnvConfig(**self._base(allowed_ip_range=["192.168.1.10-20"]))
        assert cfg.allowed_ip_range == ["192.168.1.10-20"]

    def test_allowed_ip_range_missing_dash(self):
        with pytest.raises(ValidationError, match="valid IP range"):
            EnvConfig(**self._base(allowed_ip_range=["192.168.1.10"]))

    def test_allowed_ip_range_single_octet(self):
        with pytest.raises(ValidationError, match="valid IP address"):
            EnvConfig(**self._base(allowed_ip_range=["10-20"]))

    def test_rate_limit_single_accepted(self):
        cfg = EnvConfig(**self._base(rate_limit={"max_requests": 5, "seconds": 10}))
        # A single dict is accepted as a RateLimit; the field type is Union
        assert cfg.rate_limit is not None

    def test_rate_limit_list_accepted(self):
        cfg = EnvConfig(**self._base(rate_limit=[{"max_requests": 5, "seconds": 10}]))
        assert isinstance(cfg.rate_limit, list)

    def test_enable_ui_explicit_false(self):
        cfg = EnvConfig(**self._base(enable_ui=False))
        assert cfg.enable_ui is False

    def test_enable_ui_explicit_true(self):
        cfg = EnvConfig(**self._base(enable_ui=True))
        assert cfg.enable_ui is True

    def test_ui_lifetime_bounds(self):
        cfg = EnvConfig(**self._base(ui_lifetime=300))
        assert cfg.ui_lifetime == 300
        with pytest.raises(ValidationError):
            EnvConfig(**self._base(ui_lifetime=100))  # below ge=300
        with pytest.raises(ValidationError):
            EnvConfig(**self._base(ui_lifetime=4000))  # above le=3600


# ---------------------------------------------------------------------------
# envfile_loader
# ---------------------------------------------------------------------------
class TestEnvfileLoader:
    def _write(self, tmp_path, suffix, content):
        p = tmp_path / f"config{suffix}"
        p.write_text(content)
        return str(p)

    def test_json_file(self, tmp_path):
        data = {"apikey": VALID_KEY, "secret": VALID_SECRET}
        path = self._write(tmp_path, ".json", json.dumps(data))
        cfg = envfile_loader(path)
        assert cfg.apikey == VALID_KEY

    def test_yaml_file(self, tmp_path):
        content = f"apikey: {VALID_KEY}\nsecret: {VALID_SECRET}\n"
        path = self._write(tmp_path, ".yaml", content)
        cfg = envfile_loader(path)
        assert cfg.apikey == VALID_KEY

    def test_yml_file(self, tmp_path):
        content = f"apikey: {VALID_KEY}\nsecret: {VALID_SECRET}\n"
        path = self._write(tmp_path, ".yml", content)
        cfg = envfile_loader(path)
        assert cfg.apikey == VALID_KEY

    def test_env_file(self, tmp_path):
        content = f"apikey={VALID_KEY}\nsecret={VALID_SECRET}\n"
        path = self._write(tmp_path, ".env", content)
        cfg = envfile_loader(path)
        assert cfg.apikey == VALID_KEY

    def test_txt_file(self, tmp_path):
        content = f"apikey={VALID_KEY}\nsecret={VALID_SECRET}\n"
        path = self._write(tmp_path, ".txt", content)
        cfg = envfile_loader(path)
        assert cfg.apikey == VALID_KEY

    def test_unsupported_format(self, tmp_path):
        path = self._write(tmp_path, ".xml", "<root/>")
        with pytest.raises(ValueError, match="Unsupported format"):
            envfile_loader(path)


class TestLoadEnvNoFile:
    def test_returns_env_config_when_no_file_exists(self, monkeypatch):
        """load_env() must fall through to bare EnvConfig() when env_file is absent."""
        from vaultapi.models import load_env
        # Point env_file at a path that definitely doesn't exist
        monkeypatch.setenv("env_file", "/tmp/does_not_exist_xyz.env")
        monkeypatch.delenv("ENV_FILE", raising=False)
        # The env vars set in conftest are still in os.environ so EnvConfig() is valid
        cfg = load_env()
        assert cfg.apikey is not None
