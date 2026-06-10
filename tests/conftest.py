"""Shared fixtures for VaultAPI tests."""

import base64
import os
import sqlite3
import time

import pyotp
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Stable test credentials (satisfy complexity_checker + Fernet requirements)
# ---------------------------------------------------------------------------
TOTP_SECRET = pyotp.random_base32()
FERNET_KEY = Fernet.generate_key().decode()
API_KEY = "TestApiKey1!SecurePass#Word99@XYZ"  # 32+ chars, upper/lower/digit/symbol

# ---------------------------------------------------------------------------
# Patch env vars BEFORE vaultapi is imported so models.load_env() sees them
# ---------------------------------------------------------------------------
os.environ.update(
    {
        "apikey": API_KEY,
        "secret": FERNET_KEY,
        "database": "test_vault.db",
        "enable_ui": "true",
        "totp_token": TOTP_SECRET,
        "ui_lifetime": "900",
    }
)

# Import after env is set
from vaultapi import api, models  # noqa: E402

# Initialize fernet — previously done by models.__init__() which was removed
# when IP-based access controls were stripped out.
models.session.fernet = Fernet(FERNET_KEY)

# ---------------------------------------------------------------------------
# Patch the database to in-memory SQLite connections that persist per session
# ---------------------------------------------------------------------------
_IN_MEMORY_CONN = sqlite3.connect(":memory:", check_same_thread=False)
_IN_MEMORY_AUTH_CONN = sqlite3.connect(":memory:", check_same_thread=False)


@pytest.fixture(autouse=True)
def _patch_db_connection(monkeypatch):
    """Point every database call at the in-memory connections."""
    monkeypatch.setattr(models.database, "connection", _IN_MEMORY_CONN)
    monkeypatch.setattr(models.auth_database, "connection", _IN_MEMORY_AUTH_CONN)
    yield


@pytest.fixture(autouse=True)
def _reset_auth_tables():
    """Create and clear auth tables (ui_session + blocked_hosts) around every test."""
    from vaultapi import database as _db

    _db.create_auth_tables()
    _db.delete_ui_session()
    _IN_MEMORY_AUTH_CONN.execute(f'DELETE FROM "{_db.BLOCKED_HOSTS_TABLE}"')
    _IN_MEMORY_AUTH_CONN.commit()
    yield
    _db.delete_ui_session()
    _IN_MEMORY_AUTH_CONN.execute(f'DELETE FROM "{_db.BLOCKED_HOSTS_TABLE}"')
    _IN_MEMORY_AUTH_CONN.commit()


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Clear all in-flight request records on every rate-limiter instance."""
    from vaultapi import routes

    for dep in routes.DEPENDENCIES:
        limiter = dep.dependency.__self__
        limiter.requests.clear()
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    """Drop all user tables created during a test so tests are isolated."""
    yield
    cursor = _IN_MEMORY_CONN.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for (name,) in cursor.fetchall():
        _IN_MEMORY_CONN.execute(f'DROP TABLE IF EXISTS "{name}"')
    _IN_MEMORY_CONN.commit()


# ---------------------------------------------------------------------------
# HTTP test client
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """Async HTTPX client wired directly to the FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=api.VaultAPI), base_url="http://127.0.0.1"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers re-used across test modules
# ---------------------------------------------------------------------------
def make_totp() -> str:
    return pyotp.TOTP(TOTP_SECRET).now()


def auth_headers() -> dict:
    return {"Authorization": f"Bearer {API_KEY}"}


def ui_session_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Authenticator": "VaultAPI-UI",
    }


def _set_valid_ui_session(hostname: str = "127.0.0.1") -> str:
    """Write a live session into the DB-backed ui_session table and return the token."""
    from vaultapi import database as _db

    token = base64.urlsafe_b64encode(os.urandom(32)).decode()
    expires = int(time.time()) + models.env.ui_lifetime
    _db.upsert_ui_session(token, hostname, expires, models.session.fernet)
    return token
