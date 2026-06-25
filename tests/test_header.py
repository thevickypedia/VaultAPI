"""Tests for vaultapi/header.py — generate() and validate()."""

import time

from vaultapi import header, models


class TestGenerate:
    def test_returns_signature_and_timestamp(self):
        result = header.generate("mytoken")
        assert result.startswith("Signature=")
        assert ",timestamp=" in result

    def test_timestamp_is_recent(self):
        before = int(time.time())
        result = header.generate("mytoken")
        ts = int(result.split(",timestamp=")[1])
        assert before <= ts <= before + 2

    def test_different_tokens_produce_different_signatures(self):
        h1 = header.generate("token1")
        h2 = header.generate("token2")
        sig1 = h1.split(",")[0]
        sig2 = h2.split(",")[0]
        assert sig1 != sig2


class TestValidate:
    def test_valid_header_returns_true(self):
        token = "my-secret-token"
        validity = models.env.authorization_validity
        auth = header.generate(token)
        assert header.validate(auth, token, validity) is True

    def test_wrong_token_returns_false(self):
        validity = models.env.authorization_validity
        auth = header.generate("correct-token")
        assert header.validate(auth, "wrong-token", validity) is False

    def test_expired_timestamp_returns_false(self):
        import hashlib
        import hmac as _hmac

        token = "tok"
        validity = models.env.authorization_validity
        skew_tolerance = round(validity / 5)
        old_ts = str(int(time.time()) - validity - skew_tolerance - 1)
        sig = _hmac.new(token.encode(), old_ts.encode(), hashlib.sha512).hexdigest()
        auth = f"Signature={sig},timestamp={old_ts}"
        assert header.validate(auth, token, validity) is False

    def test_future_timestamp_returns_false(self):
        import hashlib
        import hmac as _hmac

        token = "tok"
        validity = models.env.authorization_validity
        skew_tolerance = round(validity / 5)
        future_ts = str(int(time.time()) + skew_tolerance + 10)
        sig = _hmac.new(token.encode(), future_ts.encode(), hashlib.sha512).hexdigest()
        auth = f"Signature={sig},timestamp={future_ts}"
        assert header.validate(auth, token, validity) is False

    def test_malformed_header_returns_false(self):
        assert header.validate("not-valid-at-all", "token", models.env.authorization_validity) is False

    def test_missing_signature_key_returns_false(self):
        assert header.validate(f"timestamp={int(time.time())}", "token", models.env.authorization_validity) is False

    def test_missing_timestamp_key_returns_false(self):
        assert header.validate("Signature=abc123", "token", models.env.authorization_validity) is False

    def test_non_integer_timestamp_returns_false(self):
        assert header.validate("Signature=abc,timestamp=notanint", "token", models.env.authorization_validity) is False

    def test_wrong_signature_same_timestamp(self):
        token = "tok"
        validity = models.env.authorization_validity
        ts = str(int(time.time()))
        auth = f"Signature=wrongsig,timestamp={ts}"
        assert header.validate(auth, token, validity) is False

    def test_valid_token_debug_logged(self, caplog):
        import logging

        token = "logtest"
        validity = models.env.authorization_validity
        auth = header.generate(token)
        with caplog.at_level(logging.DEBUG, logger="uvicorn.default"):
            result = header.validate(auth, token, validity)
        assert result is True
