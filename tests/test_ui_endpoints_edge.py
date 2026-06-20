"""Edge-case tests for UI endpoints — sqlite errors, auth paths."""

import json as _json
import sqlite3
from unittest.mock import patch

import pytest

from tests.conftest import _set_valid_ui_session, make_totp, ui_session_headers
from vaultapi import database, models


def _h(token):
    return ui_session_headers(token)


@pytest.mark.asyncio
class TestUiCreateTableDbError:
    async def test_sqlite_error_returns_400(self, client):
        token = _set_valid_ui_session()
        with patch.object(database, "create_table", side_effect=sqlite3.OperationalError("disk full")):
            r = await client.post("/ui/table/bad_tbl", headers=_h(token))
        assert r.status_code == 400


@pytest.mark.asyncio
class TestUiDeleteTableDbError:
    async def test_sqlite_error_returns_400(self, client):
        database.create_table("del_err_ui", ["key", "value"])
        token = _set_valid_ui_session()
        with patch.object(database, "drop_table", side_effect=sqlite3.OperationalError("locked")):
            r = await client.request(
                "DELETE",
                "/ui/table/del_err_ui",
                content=_json.dumps({"totp_code": make_totp()}),
                headers={**_h(token), "Content-Type": "application/json"},
            )
        assert r.status_code == 400


@pytest.mark.asyncio
class TestUiDeleteSecretDbError:
    async def test_sqlite_error_returns_400(self, client):
        database.create_table("del_s_err", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"val")
        database.put_secret("ERR_KEY", encrypted, "del_s_err")
        token = _set_valid_ui_session()
        with patch.object(database, "remove_secret", side_effect=sqlite3.OperationalError("locked")):
            r = await client.request(
                "DELETE",
                "/ui/secret",
                content=_json.dumps(
                    {
                        "table_name": "del_s_err",
                        "key": "ERR_KEY",
                        "totp_code": make_totp(),
                    }
                ),
                headers={**_h(token), "Content-Type": "application/json"},
            )
        assert r.status_code == 400


@pytest.mark.asyncio
class TestUiGetTableDbError:
    async def test_retrieve_secrets_error_propagates(self, client):
        database.create_table("get_err_tbl", ["key", "value"])
        token = _set_valid_ui_session()
        with patch.object(database, "get_table", side_effect=sqlite3.OperationalError("boom")):
            r = await client.get("/ui/table/get_err_tbl", headers=_h(token))
        assert r.status_code == 400


@pytest.mark.asyncio
class TestUiImportBlankKey:
    async def test_blank_key_in_json_counts_as_skipped(self, client):
        """An empty-string key in JSON should be skipped (not 400)."""
        database.create_table("imp_blk", ["key", "value"])
        token = _set_valid_ui_session()
        import json as _json

        payload = {
            "table_name": "imp_blk",
            "payload": _json.dumps({"": "no_key_value", "REAL_KEY": "val"}),
            "payload_type": "json",
            "totp_code": make_totp(),
        }
        r = await client.post("/ui/import", json=payload, headers=_h(token))
        assert r.status_code == 200
        data = r.json()
        assert data["imported"] == 1
        assert data["skipped"] == 1


@pytest.mark.asyncio
class TestUiImportDbError:
    async def test_fernet_encrypt_error_counts_as_skipped(self, client):
        database.create_table("imp_ferr", ["key", "value"])
        token = _set_valid_ui_session()
        with patch.object(models.session.fernet, "encrypt", side_effect=Exception("enc fail")):
            payload = {
                "table_name": "imp_ferr",
                "payload": '{"K": "V"}',
                "payload_type": "json",
                "totp_code": make_totp(),
            }
            r = await client.post("/ui/import", json=payload, headers=_h(token))
        assert r.status_code == 200
        assert r.json()["skipped"] == 1
        assert r.json()["imported"] == 0
