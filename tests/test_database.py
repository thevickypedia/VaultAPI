"""Tests for vaultapi/database.py — all CRUD operations."""

import pytest

from vaultapi import database, models


@pytest.fixture
def table(monkeypatch):
    """Create a fresh 'test_table' and return its name."""
    database.create_table("test_table", ["key", "value"])
    yield "test_table"
    database.drop_table("test_table")


class TestTableExists:
    def test_nonexistent_table_returns_falsy(self):
        assert not database.table_exists("does_not_exist")

    def test_existing_table_returns_truthy(self, table):
        assert database.table_exists(table)


class TestListTables:
    def test_empty_by_default(self):
        # ui_session is an internal table and must never appear in list_tables()
        assert database.list_tables() == []

    def test_lists_created_table(self, table):
        assert table in database.list_tables()

    def test_multiple_tables(self):
        database.create_table("alpha", ["key", "value"])
        database.create_table("beta", ["key", "value"])
        tables = database.list_tables()
        assert "alpha" in tables
        assert "beta" in tables
        database.drop_table("alpha")
        database.drop_table("beta")


class TestCreateTable:
    def test_create_new_table(self):
        database.create_table("brand_new", ["key", "value"])
        assert database.table_exists("brand_new")
        database.drop_table("brand_new")

    def test_create_if_not_exists_idempotent(self, table):
        # Second call must not raise
        database.create_table(table, ["key", "value"])


class TestDropTable:
    def test_drop_existing_table(self, table):
        database.drop_table(table)
        assert not database.table_exists(table)

    def test_drop_nonexistent_table_no_error(self):
        # IF EXISTS means no exception
        database.drop_table("ghost_table")


class TestPutAndGetSecret:
    def test_put_and_get(self, table):
        database.put_secret("MY_KEY", b"encrypted_value", table)
        result = database.get_secret("MY_KEY", table)
        assert result == b"encrypted_value"

    def test_get_missing_key_returns_none(self, table):
        assert database.get_secret("missing", table) is None

    def test_put_overwrites_on_re_insert(self, table):
        database.put_secret("k", b"first", table)
        database.put_secret("k", b"second", table)
        # Both rows exist (no UPSERT), get_secret returns first match
        result = database.get_secret("k", table)
        assert result in (b"first", b"second")


class TestGetTable:
    def test_empty_table(self, table):
        assert database.get_table(table) == []

    def test_returns_all_rows(self, table):
        database.put_secret("a", b"1", table)
        database.put_secret("b", b"2", table)
        rows = database.get_table(table)
        assert len(rows) == 2
        assert ("a", b"1") in rows
        assert ("b", b"2") in rows


class TestRemoveSecret:
    def test_remove_existing_secret(self, table):
        database.put_secret("to_delete", b"val", table)
        database.remove_secret("to_delete", table)
        assert database.get_secret("to_delete", table) is None

    def test_remove_nonexistent_key_no_error(self, table):
        # Should not raise
        database.remove_secret("ghost_key", table)


class TestUiSession:
    def test_get_returns_none_when_empty(self):
        database.delete_ui_session()
        assert database.get_ui_session(models.session.fernet) is None

    def test_upsert_and_get_roundtrip(self):
        import time

        expires = int(time.time()) + 900
        database.upsert_ui_session("tok123", "myhost", expires, models.session.fernet)
        result = database.get_ui_session(models.session.fernet)
        assert result["token"] == "tok123"
        assert result["host"] == "myhost"
        assert result["exp"] == expires

    def test_upsert_replaces_previous_session(self):
        import time

        database.upsert_ui_session(
            "old-tok", "h1", int(time.time()) + 900, models.session.fernet
        )
        database.upsert_ui_session(
            "new-tok", "h2", int(time.time()) + 900, models.session.fernet
        )
        result = database.get_ui_session(models.session.fernet)
        assert result["token"] == "new-tok"
        assert result["host"] == "h2"

    def test_delete_clears_session(self):
        import time

        database.upsert_ui_session(
            "tok", "h", int(time.time()) + 900, models.session.fernet
        )
        database.delete_ui_session()
        assert database.get_ui_session(models.session.fernet) is None

    def test_tampered_blob_returns_none(self):
        import time

        database.upsert_ui_session(
            "tok", "h", int(time.time()) + 900, models.session.fernet
        )
        # Overwrite the blob with garbage so Fernet raises on decrypt
        with models.database.connection:
            models.database.connection.execute(
                f'UPDATE "{database.UI_SESSION_TABLE}" SET payload = ?',
                (b"not-fernet",),
            )
            models.database.connection.commit()
        assert database.get_ui_session(models.session.fernet) is None

    def test_ui_session_excluded_from_list_tables(self):
        assert database.UI_SESSION_TABLE not in database.list_tables()
