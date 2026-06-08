"""Tests for vaultapi/payload.py — Pydantic models."""

import pytest
from pydantic import ValidationError

from vaultapi.payload import DeleteSecret, PutSecret


class TestDeleteSecret:
    def test_defaults(self):
        ds = DeleteSecret(key="MY_KEY")
        assert ds.table_name == "default"

    def test_custom_table(self):
        ds = DeleteSecret(key="K", table_name="prod")
        assert ds.table_name == "prod"

    def test_key_required(self):
        with pytest.raises(ValidationError):
            DeleteSecret()


class TestPutSecret:
    def test_dict_secrets(self):
        ps = PutSecret(secrets={"K": "V"})
        assert ps.secrets == {"K": "V"}
        assert ps.table_name == "default"

    def test_string_secrets(self):
        ps = PutSecret(secrets="encrypted_blob")
        assert isinstance(ps.secrets, str)

    def test_custom_table(self):
        ps = PutSecret(secrets={"K": "V"}, table_name="staging")
        assert ps.table_name == "staging"

    def test_secrets_required(self):
        with pytest.raises(ValidationError):
            PutSecret()
