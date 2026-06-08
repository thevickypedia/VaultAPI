"""Edge-case tests for api_endpoints — sqlite errors, docs redirect, single-key log path."""

import sqlite3
from unittest.mock import patch

import pytest

from tests.conftest import auth_headers
from vaultapi import api_endpoints, database, exceptions, models


@pytest.mark.asyncio
class TestRetrieveSecretSqliteError:
    async def test_retrieve_secret_db_error_raises_api_response(self):
        with patch.object(
            database, "get_secret", side_effect=sqlite3.OperationalError("disk full")
        ):
            with pytest.raises(exceptions.APIResponse) as exc:
                await api_endpoints.retrieve_secret("KEY", "tbl")
            assert exc.value.status_code == 400

    async def test_retrieve_secrets_with_keys_propagates_error(self):
        with patch.object(
            database, "get_secret", side_effect=sqlite3.OperationalError("bad")
        ):
            with pytest.raises(exceptions.APIResponse):
                await api_endpoints.retrieve_secrets("tbl", keys=["KEY"])

    async def test_retrieve_secrets_full_table_db_error(self):
        with patch.object(
            database, "get_table", side_effect=sqlite3.OperationalError("oops")
        ):
            with pytest.raises(exceptions.APIResponse) as exc:
                await api_endpoints.retrieve_secrets("tbl")
            assert exc.value.status_code == 400


@pytest.mark.asyncio
class TestGetSecretSingleKeyNotFound:
    async def test_single_missing_key_logs_specific_message(self, client):
        database.create_table("log_tbl", ["key", "value"])
        r = await client.get(
            "/get-secret?key=ONLY_ONE&table_name=log_tbl", headers=auth_headers()
        )
        assert r.status_code == 404

    async def test_multiple_missing_keys_uses_plural_log_path(self, client):
        # Both K1 and K2 absent → the else-branch logger fires (keys_ct > 1, all missing)
        database.create_table("log_multi", ["key", "value"])
        r = await client.get(
            "/get-secret?key=K1,K2&table_name=log_multi", headers=auth_headers()
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestDeleteSecretSqliteError:
    async def test_delete_db_error_raises(self, client):
        import json as _json

        database.create_table("del_err_tbl", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("ERRANT", encrypted, "del_err_tbl")
        with patch.object(
            database, "remove_secret", side_effect=sqlite3.OperationalError("locked")
        ):
            payload = {"key": "ERRANT", "table_name": "del_err_tbl"}
            r = await client.request(
                "DELETE",
                "/delete-secret",
                content=_json.dumps(payload),
                headers={**auth_headers(), "Content-Type": "application/json"},
            )
        assert r.status_code == 417  # EXPECTATION_FAILED


@pytest.mark.asyncio
class TestCreateTableSqliteError:
    async def test_create_table_db_error(self, client):
        with patch.object(
            database, "create_table", side_effect=sqlite3.OperationalError("no space")
        ):
            r = await client.post(
                "/create-table?table_name=err_tbl", headers=auth_headers()
            )
        assert r.status_code == 417


@pytest.mark.asyncio
class TestDeleteTableSqliteError:
    async def test_delete_table_db_error(self, client):
        database.create_table("dtbl_err", ["key", "value"])
        with patch.object(
            database, "drop_table", side_effect=sqlite3.OperationalError("locked")
        ):
            r = await client.delete(
                "/delete-table?table_name=dtbl_err", headers=auth_headers()
            )
        assert r.status_code == 417


@pytest.mark.asyncio
class TestDocsRedirect:
    async def test_docs_endpoint_returns_redirect(self):
        from fastapi.responses import RedirectResponse

        resp = await api_endpoints.docs()
        assert isinstance(resp, RedirectResponse)
        assert resp.headers["location"] == "/docs"
