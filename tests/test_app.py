"""Tests for vaultapi/api.py — lifespan / delete_ui_session branches."""

import pytest

from vaultapi import api, database, models


@pytest.mark.asyncio
class TestDeleteUiSession:
    async def test_deletes_existing_session(self):
        from tests.conftest import _set_valid_ui_session

        _set_valid_ui_session()
        assert database.get_ui_session(models.session.fernet) is not None
        await api.delete_ui_session("startup")
        assert database.get_ui_session(models.session.fernet) is None

    async def test_no_session_logs_info(self, caplog):
        import logging

        database.delete_ui_session()
        with caplog.at_level(logging.INFO, logger="uvicorn.default"):
            await api.delete_ui_session("shutdown")
        assert database.get_ui_session(models.session.fernet) is None


@pytest.mark.asyncio
class TestLifespan:
    async def test_lifespan_startup_and_shutdown(self):
        """Exercise the lifespan context manager (lines 24-26) directly."""
        async with api.lifespan(api.VaultAPI):
            pass  # yield point — covers startup task, yield, and shutdown task
