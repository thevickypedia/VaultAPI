"""Tests for API endpoints via HTTP (no UI auth)."""

import pytest

from tests.conftest import api_advanced_headers, auth_headers
from vaultapi import database, models


@pytest.mark.asyncio
class TestHealth:
    async def test_health_ok(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["STATUS"] == "OK"


@pytest.mark.asyncio
class TestVersion:
    async def test_version_ok(self, client):
        r = await client.get("/version", headers=auth_headers())
        assert r.status_code == 200


@pytest.mark.asyncio
class TestListTables:
    async def test_unauthorized_without_key(self, client):
        r = await client.get("/list-tables")
        assert r.status_code in (401, 403)

    async def test_returns_empty_list(self, client):
        r = await client.get("/list-tables", headers=auth_headers())
        assert r.status_code == 200

    async def test_returns_created_tables(self, client):
        database.create_table("mytable", ["key", "value"])
        r = await client.get("/list-tables", headers=auth_headers())
        assert r.status_code == 200


@pytest.mark.asyncio
class TestCreateAndDeleteTable:
    async def test_create_table(self, client):
        r = await client.post("/create-table?table_name=newtable", headers=auth_headers())
        assert r.status_code == 200
        assert database.table_exists("newtable")

    async def test_create_duplicate_table(self, client):
        database.create_table("duptable", ["key", "value"])
        r = await client.post("/create-table?table_name=duptable", headers=auth_headers())
        assert r.status_code == 409

    async def test_delete_existing_table(self, client):
        database.create_table("todel", ["key", "value"])
        r = await client.delete("/delete-table?table_name=todel", headers=api_advanced_headers())
        assert r.status_code == 200
        assert not database.table_exists("todel")

    async def test_delete_nonexistent_table(self, client):
        r = await client.delete("/delete-table?table_name=ghost", headers=api_advanced_headers())
        assert r.status_code == 404


@pytest.mark.asyncio
class TestRenameTable:
    async def test_rename_existing_table(self, client):
        database.create_table("old_name", ["key", "value"])
        r = await client.patch(
            "/rename-table?table_name=old_name",
            json={"new_name": "new_name"},
            headers=api_advanced_headers(),
        )
        assert r.status_code == 200
        assert not database.table_exists("old_name")
        assert database.table_exists("new_name")

    async def test_rename_nonexistent_table(self, client):
        r = await client.patch(
            "/rename-table?table_name=ghost",
            json={"new_name": "whatever"},
            headers=api_advanced_headers(),
        )
        assert r.status_code == 404

    async def test_rename_to_existing_name_returns_409(self, client):
        database.create_table("src_tbl", ["key", "value"])
        database.create_table("dst_tbl", ["key", "value"])
        r = await client.patch(
            "/rename-table?table_name=src_tbl",
            json={"new_name": "dst_tbl"},
            headers=api_advanced_headers(),
        )
        assert r.status_code == 409

    async def test_rename_empty_new_name_returns_400(self, client):
        database.create_table("src_tbl2", ["key", "value"])
        r = await client.patch(
            "/rename-table?table_name=src_tbl2",
            json={"new_name": ""},
            headers=api_advanced_headers(),
        )
        assert r.status_code == 400

    async def test_rename_requires_auth(self, client):
        r = await client.patch(
            "/rename-table?table_name=any",
            json={"new_name": "other"},
        )
        assert r.status_code in (401, 403)


@pytest.mark.asyncio
class TestPutAndGetSecret:
    async def test_put_secret_to_existing_table(self, client):
        database.create_table("vault", ["key", "value"])
        payload = {"secrets": {"DB_PASS": "hunter2"}, "table_name": "vault"}
        r = await client.put("/put-secret", json=payload, headers=api_advanced_headers())
        assert r.status_code == 200

    async def test_put_secret_to_missing_table(self, client):
        payload = {"secrets": {"KEY": "val"}, "table_name": "missing_table"}
        r = await client.put("/put-secret", json=payload, headers=api_advanced_headers())
        assert r.status_code == 404

    async def test_get_single_secret(self, client):
        database.create_table("vault2", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"mypassword")
        database.put_secret("MY_SECRET", encrypted, "vault2")
        r = await client.get("/get-secret?key=MY_SECRET&table_name=vault2", headers=auth_headers())
        assert r.status_code == 200

    async def test_get_missing_secret(self, client):
        database.create_table("vault3", ["key", "value"])
        r = await client.get("/get-secret?key=NOPE&table_name=vault3", headers=auth_headers())
        assert r.status_code == 404

    async def test_get_secret_empty_key(self, client):
        database.create_table("vault4", ["key", "value"])
        r = await client.get("/get-secret?key=&table_name=vault4", headers=auth_headers())
        assert r.status_code == 400

    async def test_get_multiple_secrets_partial(self, client):
        database.create_table("vault5", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"val1")
        database.put_secret("K1", encrypted, "vault5")
        r = await client.get("/get-secret?key=K1,K2&table_name=vault5", headers=auth_headers())
        assert r.status_code == 206

    async def test_get_table_full(self, client):
        database.create_table("fulltbl", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("k", encrypted, "fulltbl")
        r = await client.get("/get-table?table_name=fulltbl", headers=auth_headers())
        assert r.status_code == 200


@pytest.mark.asyncio
class TestDeleteSecret:
    async def test_delete_existing_secret(self, client):
        import json as _json

        database.create_table("ds_table", ["key", "value"])
        encrypted = models.session.fernet.encrypt(b"v")
        database.put_secret("DEL_ME", encrypted, "ds_table")
        payload = {"key": "DEL_ME", "table_name": "ds_table"}
        r = await client.request(
            "DELETE",
            "/delete-secret",
            content=_json.dumps(payload),
            headers={**api_advanced_headers(), "Content-Type": "application/json"},
        )
        assert r.status_code == 200

    async def test_delete_nonexistent_secret(self, client):
        import json as _json

        database.create_table("ds_table2", ["key", "value"])
        payload = {"key": "GHOST", "table_name": "ds_table2"}
        r = await client.request(
            "DELETE",
            "/delete-secret",
            content=_json.dumps(payload),
            headers={**api_advanced_headers(), "Content-Type": "application/json"},
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestPutSecretTransitEncrypted:
    async def test_put_transit_encrypted_secrets(self, client):
        from vaultapi import transit

        database.create_table("transit_tbl", ["key", "value"])
        encrypted_payload = transit.encrypt({"TK": "tv"})
        payload = {"secrets": encrypted_payload, "table_name": "transit_tbl"}
        r = await client.put("/put-secret", json=payload, headers=api_advanced_headers())
        assert r.status_code == 200
