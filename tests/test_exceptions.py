"""Tests for vaultapi/exceptions.py."""

import pytest
from fastapi.exceptions import HTTPException

from vaultapi.exceptions import APIResponse


class TestAPIResponse:
    def test_is_http_exception(self):
        exc = APIResponse(status_code=404, detail="Not Found")
        assert isinstance(exc, HTTPException)

    def test_status_code(self):
        exc = APIResponse(status_code=401, detail="Unauthorized")
        assert exc.status_code == 401

    def test_detail(self):
        exc = APIResponse(status_code=200, detail={"key": "value"})
        assert exc.detail == {"key": "value"}

    def test_raiseable(self):
        with pytest.raises(APIResponse) as exc_info:
            raise APIResponse(status_code=403, detail="Forbidden")
        assert exc_info.value.status_code == 403
