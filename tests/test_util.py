"""Tests for vaultapi/util.py — dotenv_to_table and transit_decrypt."""

import pytest

from vaultapi import database, models
from vaultapi.util import dotenv_to_table, transit_decrypt


@pytest.fixture
def dotenv_file(tmp_path):
    p = tmp_path / "sample.env"
    p.write_text("SECRET_A=value_a\nSECRET_B=value_b\n")
    return str(p)


class TestDotenvToTable:
    def test_creates_new_table_and_stores_secrets(self, dotenv_file):
        dotenv_to_table("util_new", dotenv_file)
        assert database.table_exists("util_new")
        raw = database.get_secret("SECRET_A", "util_new")
        assert raw is not None
        assert models.session.fernet.decrypt(raw) == b"value_a"

    def test_drop_existing_and_recreate(self, dotenv_file):
        database.create_table("util_drop", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"old_val")
        database.put_secret("OLD_KEY", encrypted, "util_drop")
        # drop_existing=True should replace the table
        dotenv_to_table("util_drop", dotenv_file, drop_existing=True)
        assert database.get_secret("OLD_KEY", "util_drop") is None
        assert database.get_secret("SECRET_A", "util_drop") is not None

    def test_warns_on_existing_table_without_drop(self, dotenv_file):
        database.create_table("util_warn", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"existing")
        database.put_secret("EXISTING", encrypted, "util_warn")
        # Should log a warning but not raise
        dotenv_to_table("util_warn", dotenv_file, drop_existing=False)
        # New keys present
        assert database.get_secret("SECRET_A", "util_warn") is not None

    def test_creates_table_if_not_exists(self, dotenv_file):
        # Table doesn't exist yet — should create it automatically
        dotenv_to_table("util_auto_create", dotenv_file)
        assert database.table_exists("util_auto_create")


class TestDotenvToTableUnexpectedError:
    def test_unexpected_sqlite_error_is_reraised(self, dotenv_file):
        """An OperationalError with an unexpected message must propagate."""
        import sqlite3 as _sqlite3
        from unittest.mock import patch

        # Simulate drop_existing=False so the get_table path is taken,
        # then inject an error that is NOT "no such table: …"
        with patch(
            "vaultapi.database.get_table",
            side_effect=_sqlite3.OperationalError("disk I/O error"),
        ):
            with pytest.raises(_sqlite3.OperationalError, match="disk I/O error"):
                dotenv_to_table("wont_matter", dotenv_file, drop_existing=False)


class TestTransitDecrypt:
    def test_roundtrip(self):
        import base64
        import hashlib
        import json
        import secrets as _secrets
        import time

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        payload = {"MY_KEY": "MY_VALUE"}
        epoch = int(time.time()) // models.env.transit_time_bucket
        hash_obj = hashlib.sha256(f"{epoch}.{models.env.apikey}".encode())
        aes_key = hash_obj.digest()[: models.env.transit_key_length]
        nonce = _secrets.token_bytes(12)
        encoded = json.dumps(payload).encode()
        ciphertext = nonce + AESGCM(aes_key).encrypt(nonce, encoded, b"")
        b64 = base64.b64encode(ciphertext).decode("utf-8")

        result = transit_decrypt(b64)
        assert result == payload

    def test_accepts_bytes(self):
        import hashlib
        import json
        import secrets as _secrets
        import time

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        payload = {"K": "V"}
        epoch = int(time.time()) // models.env.transit_time_bucket
        hash_obj = hashlib.sha256(f"{epoch}.{models.env.apikey}".encode())
        aes_key = hash_obj.digest()[: models.env.transit_key_length]
        nonce = _secrets.token_bytes(12)
        encoded = json.dumps(payload).encode()
        ciphertext_bytes = nonce + AESGCM(aes_key).encrypt(nonce, encoded, b"")

        result = transit_decrypt(ciphertext_bytes)
        assert result == payload
