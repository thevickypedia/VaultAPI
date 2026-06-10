"""Tests for UI endpoints — login, CRUD via session tokens, import."""

from unittest.mock import patch

import pytest

from tests.conftest import (
    API_KEY,
    FERNET_KEY,
    _set_valid_ui_session,
    make_totp,
    ui_session_headers,
)
from vaultapi import database, models


def _ui_headers(token):
    return ui_session_headers(token)


# ---------------------------------------------------------------------------
# / (index)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestIndex:
    async def test_returns_html(self, client):
        r = await client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert b"VaultAPI" in r.content

    async def test_blocked_host_returns_403(self, client):
        with patch("vaultapi.ui_endpoints.models.session") as mock_session:
            mock_session.allowed_origins = set()
            r = await client.get("/")
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# /ui/login
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiLogin:
    async def test_valid_credentials_returns_token(self, client):
        r = await client.post(
            "/ui/login",
            json={"apikey": API_KEY, "secret": FERNET_KEY, "totp_code": make_totp()},
        )
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert "expires" in data

    async def test_wrong_apikey_returns_401(self, client):
        r = await client.post(
            "/ui/login",
            json={
                "apikey": "wrong-key",
                "secret": FERNET_KEY,
                "totp_code": make_totp(),
            },
        )
        assert r.status_code == 401

    async def test_wrong_secret_returns_401(self, client):
        r = await client.post(
            "/ui/login",
            json={
                "apikey": API_KEY,
                "secret": "wrong-secret",
                "totp_code": make_totp(),
            },
        )
        assert r.status_code == 401

    async def test_wrong_totp_returns_401(self, client):
        r = await client.post(
            "/ui/login",
            json={"apikey": API_KEY, "secret": FERNET_KEY, "totp_code": "000000"},
        )
        assert r.status_code == 401

    async def test_forbidden_from_unknown_host(self, client):
        original = models.session.allowed_origins.copy()
        models.session.allowed_origins.clear()
        models.session.allowed_origins.add("10.99.99.99")
        try:
            r = await client.post(
                "/ui/login",
                json={
                    "apikey": API_KEY,
                    "secret": FERNET_KEY,
                    "totp_code": make_totp(),
                },
            )
            assert r.status_code == 403
        finally:
            models.session.allowed_origins.clear()
            models.session.allowed_origins.update(original)

    async def test_totp_exception_returns_401(self, client):
        with patch("pyotp.TOTP.verify", side_effect=Exception("boom")):
            r = await client.post(
                "/ui/login",
                json={"apikey": API_KEY, "secret": FERNET_KEY, "totp_code": "123456"},
            )
        assert r.status_code == 401

    async def test_apikey_with_backslash_prefix_decoded(self, client):
        r = await client.post(
            "/ui/login",
            json={"apikey": "\\nwrong", "secret": FERNET_KEY, "totp_code": make_totp()},
        )
        assert r.status_code in (401, 429)


# ---------------------------------------------------------------------------
# /ui/logout
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiLogout:
    async def test_logout_invalidates_session(self, client):
        token = _set_valid_ui_session()
        r = await client.post("/ui/logout", headers=_ui_headers(token))
        assert r.status_code == 200
        # Token must no longer be accepted after logout
        r2 = await client.get("/ui/tables", headers=_ui_headers(token))
        assert r2.status_code == 401

    async def test_logout_requires_auth(self, client):
        r = await client.post(
            "/ui/logout",
            headers={"Authorization": "Bearer bad", "Authenticator": "VaultAPI-UI"},
        )
        assert r.status_code == 401

    async def test_logout_after_logout_returns_401(self, client):
        token = _set_valid_ui_session()
        await client.post("/ui/logout", headers=_ui_headers(token))
        r = await client.post("/ui/logout", headers=_ui_headers(token))
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# /ui/tables
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiListTables:
    async def test_requires_auth(self, client):
        r = await client.get("/ui/tables", headers={"Authorization": "Bearer bad"})
        assert r.status_code in (401, 403)

    async def test_returns_empty_list(self, client):
        token = _set_valid_ui_session()
        r = await client.get("/ui/tables", headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["tables"] == []

    async def test_returns_created_tables(self, client):
        database.create_table("visible_table", ["key", "value"])
        token = _set_valid_ui_session()
        r = await client.get("/ui/tables", headers=_ui_headers(token))
        assert r.status_code == 200
        assert "visible_table" in r.json()["tables"]


# ---------------------------------------------------------------------------
# /ui/table/{table_name}  (GET)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiGetTable:
    async def test_get_existing_table(self, client):
        database.create_table("t1", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"myval")
        database.put_secret("MYKEY", encrypted, "t1")
        token = _set_valid_ui_session()
        r = await client.get("/ui/table/t1", headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["secrets"]["MYKEY"] == "myval"

    async def test_get_missing_table_returns_404(self, client):
        token = _set_valid_ui_session()
        r = await client.get("/ui/table/no_such_table", headers=_ui_headers(token))
        assert r.status_code == 404

    async def test_get_empty_table(self, client):
        database.create_table("empty_t", ["key", "value"])
        token = _set_valid_ui_session()
        r = await client.get("/ui/table/empty_t", headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["secrets"] == {}


# ---------------------------------------------------------------------------
# /ui/table/{table_name}  (POST / DELETE)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiCreateDeleteTable:
    async def test_create_table(self, client):
        token = _set_valid_ui_session()
        r = await client.post("/ui/table/brand_new", headers=_ui_headers(token))
        assert r.status_code == 200
        assert database.table_exists("brand_new")

    async def _delete_table(self, client, name, totp_code, headers):
        import json as _json

        return await client.request(
            "DELETE",
            f"/ui/table/{name}",
            content=_json.dumps({"totp_code": totp_code}),
            headers={**headers, "Content-Type": "application/json"},
        )

    async def test_delete_existing_table(self, client):
        database.create_table("to_delete", ["key", "value"])
        token = _set_valid_ui_session()
        r = await self._delete_table(
            client, "to_delete", make_totp(), _ui_headers(token)
        )
        assert r.status_code == 200
        assert not database.table_exists("to_delete")

    async def test_delete_table_wrong_totp_returns_401(self, client):
        database.create_table("totp_guard_tbl", ["key", "value"])
        token = _set_valid_ui_session()
        r = await self._delete_table(
            client, "totp_guard_tbl", "000000", _ui_headers(token)
        )
        assert r.status_code == 401
        assert database.table_exists("totp_guard_tbl")

    async def test_delete_missing_table_returns_404(self, client):
        token = _set_valid_ui_session()
        r = await self._delete_table(
            client, "ghost_table", make_totp(), _ui_headers(token)
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# /ui/secret  (PUT)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiPutSecret:
    async def test_put_secret_to_existing_table(self, client):
        database.create_table("put_tbl", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {"table_name": "put_tbl", "key": "MY_KEY", "value": "my_value"}
        r = await client.put("/ui/secret", json=payload, headers=_ui_headers(token))
        assert r.status_code == 200
        # Verify it was actually stored
        assert database.get_secret("MY_KEY", "put_tbl") is not None

    async def test_put_secret_empty_key_returns_400(self, client):
        database.create_table("put_tbl2", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {"table_name": "put_tbl2", "key": "", "value": "val"}
        r = await client.put("/ui/secret", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_put_secret_missing_table_returns_404(self, client):
        token = _set_valid_ui_session()
        payload = {"table_name": "no_table", "key": "K", "value": "v"}
        r = await client.put("/ui/secret", json=payload, headers=_ui_headers(token))
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# /ui/secret  (DELETE)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiDeleteSecret:
    async def _delete(self, client, path, payload, headers):
        import json as _json

        return await client.request(
            "DELETE",
            path,
            content=_json.dumps(payload),
            headers={**headers, "Content-Type": "application/json"},
        )

    async def test_delete_existing_secret(self, client):
        database.create_table("del_tbl", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("DEL_KEY", encrypted, "del_tbl")
        token = _set_valid_ui_session()
        r = await self._delete(
            client,
            "/ui/secret",
            {"table_name": "del_tbl", "key": "DEL_KEY", "totp_code": make_totp()},
            _ui_headers(token),
        )
        assert r.status_code == 200
        assert database.get_secret("DEL_KEY", "del_tbl") is None

    async def test_delete_secret_wrong_totp_returns_401(self, client):
        database.create_table("del_totp_tbl", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("GUARDED_KEY", encrypted, "del_totp_tbl")
        token = _set_valid_ui_session()
        r = await self._delete(
            client,
            "/ui/secret",
            {"table_name": "del_totp_tbl", "key": "GUARDED_KEY", "totp_code": "000000"},
            _ui_headers(token),
        )
        assert r.status_code == 401
        assert database.get_secret("GUARDED_KEY", "del_totp_tbl") is not None

    async def test_delete_empty_key_returns_400(self, client):
        token = _set_valid_ui_session()
        r = await self._delete(
            client,
            "/ui/secret",
            {"table_name": "any", "key": "", "totp_code": make_totp()},
            _ui_headers(token),
        )
        assert r.status_code == 400

    async def test_delete_nonexistent_secret_returns_404(self, client):
        database.create_table("del_tbl2", ["key", "value"])
        token = _set_valid_ui_session()
        r = await self._delete(
            client,
            "/ui/secret",
            {"table_name": "del_tbl2", "key": "GHOST", "totp_code": make_totp()},
            _ui_headers(token),
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# /ui/import  (POST)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestUiImportSecrets:
    async def test_import_json(self, client):
        database.create_table("imp_json", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_json",
            "payload": '{"DB_URL": "postgres://localhost/db", "API_KEY": "abc123"}',
            "payload_type": "json",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 200
        data = r.json()
        assert data["imported"] == 2
        assert data["skipped"] == 0

    async def test_import_yaml(self, client):
        database.create_table("imp_yaml", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_yaml",
            "payload": "DB_HOST: localhost\nDB_PORT: '5432'\n",
            "payload_type": "yaml",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["imported"] == 2

    async def test_import_env(self, client):
        database.create_table("imp_env", ["key", "value"])
        token = _set_valid_ui_session()
        env_text = (
            "# comment\n"
            "API_SECRET=hunter2\n"
            'QUOTED="double quoted value"\n'
            "SINGLE='single quoted'\n"
            "\n"
            "PLAIN=noQuotes\n"
        )
        payload = {
            "table_name": "imp_env",
            "payload": env_text,
            "payload_type": "env",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["imported"] == 4

    async def test_import_env_skips_lines_without_equals(self, client):
        database.create_table("imp_env2", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_env2",
            "payload": "no_equals_sign_here\nVALID=ok\n",
            "payload_type": "env",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 200
        assert r.json()["imported"] == 1

    async def test_import_missing_table_returns_404(self, client):
        token = _set_valid_ui_session()
        payload = {
            "table_name": "no_table",
            "payload": '{"k": "v"}',
            "payload_type": "json",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 404

    async def test_import_invalid_json_returns_400(self, client):
        database.create_table("imp_bad", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_bad",
            "payload": "{not valid json",
            "payload_type": "json",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_import_json_non_dict_returns_400(self, client):
        database.create_table("imp_arr", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_arr",
            "payload": '["a", "b"]',
            "payload_type": "json",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_import_yaml_non_dict_returns_400(self, client):
        database.create_table("imp_ylist", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_ylist",
            "payload": "- item1\n- item2\n",
            "payload_type": "yaml",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_import_unsupported_type_returns_400(self, client):
        database.create_table("imp_unk", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_unk",
            "payload": "anything",
            "payload_type": "xml",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_import_empty_payload_returns_400(self, client):
        database.create_table("imp_empty", ["key", "value"])
        token = _set_valid_ui_session()
        payload = {
            "table_name": "imp_empty",
            "payload": "{}",
            "payload_type": "json",
        }
        r = await client.post("/ui/import", json=payload, headers=_ui_headers(token))
        assert r.status_code == 400

    async def test_import_requires_auth(self, client):
        payload = {
            "table_name": "any",
            "payload": '{"k": "v"}',
            "payload_type": "json",
        }
        r = await client.post(
            "/ui/import",
            json=payload,
            headers={"Authorization": "Bearer wrong"},
        )
        assert r.status_code in (401, 403)
