"""Tests for vaultapi/database.py — all CRUD operations."""

import pytest

from tests.conftest import _IN_MEMORY_AUTH_CONN
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

        database.upsert_ui_session("old-tok", "h1", int(time.time()) + 900, models.session.fernet)
        database.upsert_ui_session("new-tok", "h2", int(time.time()) + 900, models.session.fernet)
        result = database.get_ui_session(models.session.fernet)
        assert result["token"] == "new-tok"
        assert result["host"] == "h2"

    def test_delete_clears_session(self):
        import time

        database.upsert_ui_session("tok", "h", int(time.time()) + 900, models.session.fernet)
        database.delete_ui_session()
        assert database.get_ui_session(models.session.fernet) is None

    def test_tampered_blob_returns_none(self):
        import time

        database.upsert_ui_session("tok", "h", int(time.time()) + 900, models.session.fernet)
        # Overwrite the blob with garbage so Fernet raises on decrypt
        with _IN_MEMORY_AUTH_CONN:
            _IN_MEMORY_AUTH_CONN.execute(
                f'UPDATE "{database.UI_SESSION_TABLE}" SET payload = ?',
                (b"not-fernet",),
            )
            _IN_MEMORY_AUTH_CONN.commit()
        assert database.get_ui_session(models.session.fernet) is None

    def test_ui_session_not_in_secrets_db(self):
        assert database.UI_SESSION_TABLE not in database.list_tables()


class TestBlockedHosts:
    def test_host_not_blocked_initially(self):
        assert not database.is_host_blocked("1.2.3.4")
        assert database.get_blocked_until("1.2.3.4") is None

    def test_increment_creates_entry(self):
        database.increment_failed_auth("1.2.3.4")
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("1.2.3.4",),
        ).fetchone()
        assert row is not None and row[0] == 1

    def test_increment_accumulates(self):
        for _ in range(2):
            database.increment_failed_auth("2.3.4.5")
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("2.3.4.5",),
        ).fetchone()
        assert row[0] == 2

    def test_not_blocked_below_limit(self):
        for _ in range(database.FAILED_AUTH_LIMIT - 1):
            database.increment_failed_auth("4.5.6.7")
        assert not database.is_host_blocked("4.5.6.7")

    def test_blocked_at_limit_sets_5min_cooloff(self):
        import time as _time

        before = int(_time.time())
        for _ in range(3):
            database.increment_failed_auth("3.4.5.6")
        auth_counter = database.get_blocked_until("3.4.5.6")
        assert auth_counter is not None
        assert auth_counter.blocked_until >= before + 299
        assert database.is_host_blocked("3.4.5.6")

    def test_five_failures_sets_15min_cooloff(self):
        import time as _time

        before = int(_time.time())
        for _ in range(5):
            database.increment_failed_auth("5.6.7.8")
        auth_counter = database.get_blocked_until("5.6.7.8")
        assert auth_counter is not None
        assert auth_counter.blocked_until >= before + 899

    def test_ten_failures_sets_1day_cooloff(self):
        import time as _time

        before = int(_time.time())
        for _ in range(10):
            database.increment_failed_auth("6.7.8.9")
        auth_counter = database.get_blocked_until("6.7.8.9")
        assert auth_counter is not None
        assert auth_counter.blocked_until >= before + 86399

    def test_expired_cooloff_clears_timer_but_keeps_count(self, monkeypatch):
        import time as _time

        for _ in range(3):
            database.increment_failed_auth("7.8.9.0")
        # Wind clock past the 5-minute block
        monkeypatch.setattr(
            "vaultapi.database.time",
            type("_T", (), {"time": staticmethod(lambda: _time.time() + 400)})(),
        )
        assert database.get_blocked_until("7.8.9.0") is None
        assert not database.is_host_blocked("7.8.9.0")
        # Row must survive with the original failure count intact
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth, blocked_until FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("7.8.9.0",),
        ).fetchone()
        assert row is not None
        assert row[0] == 3
        assert row[1] is None

    def test_failure_count_persists_across_cooloff_cycles(self):
        import time as _time
        from unittest.mock import patch

        # 3 failures → 5-min block; cooloff expires; 2 more failures → count=5 → 15-min block
        for _ in range(3):
            database.increment_failed_auth("7.8.9.1")
        # Simulate time advancing past the 5-minute window to expire the block
        future = _time.time() + 400
        with patch("vaultapi.database.time") as mock_time:
            mock_time.time.return_value = future
            database.get_blocked_until("7.8.9.1")  # trigger timer clear
        database.increment_failed_auth("7.8.9.1")
        database.increment_failed_auth("7.8.9.1")
        row = _IN_MEMORY_AUTH_CONN.execute(
            f'SELECT failed_auth, blocked_until FROM "{database.BLOCKED_HOSTS_TABLE}" WHERE host = ?',
            ("7.8.9.1",),
        ).fetchone()
        assert row[0] == 5
        assert row[1] is not None  # escalated to 15-min tier

    def test_remove_blocked_host(self):
        for _ in range(3):
            database.increment_failed_auth("8.9.0.1")
        assert database.is_host_blocked("8.9.0.1")
        database.remove_blocked_host("8.9.0.1")
        assert not database.is_host_blocked("8.9.0.1")

    def test_remove_nonexistent_host_no_error(self):
        database.remove_blocked_host("0.0.0.0")  # should not raise

    def test_reset_failed_auth_clears_cooloff(self):
        for _ in range(3):
            database.increment_failed_auth("9.0.1.2")
        assert database.is_host_blocked("9.0.1.2")
        database.reset_failed_auth("9.0.1.2")
        assert not database.is_host_blocked("9.0.1.2")

    def test_reset_nonexistent_host_no_error(self):
        database.reset_failed_auth("9.9.9.9")  # should not raise
