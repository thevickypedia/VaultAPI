"""Tests for vaultapi/transit.py — AES-GCM encrypt/decrypt round-trips."""

import base64

import pytest

from vaultapi import transit


class TestStringToAesKey:
    def test_length_16(self):
        key = transit.string_to_aes_key("hello", 16)
        assert len(key) == 16

    def test_length_24(self):
        key = transit.string_to_aes_key("hello", 24)
        assert len(key) == 24

    def test_length_32(self):
        key = transit.string_to_aes_key("hello", 32)
        assert len(key) == 32

    def test_deterministic(self):
        k1 = transit.string_to_aes_key("same-input", 32)
        k2 = transit.string_to_aes_key("same-input", 32)
        assert k1 == k2

    def test_different_inputs_differ(self):
        k1 = transit.string_to_aes_key("input-a", 32)
        k2 = transit.string_to_aes_key("input-b", 32)
        assert k1 != k2


class TestEncryptDecrypt:
    def test_roundtrip_simple(self):
        payload = {"key": "value"}
        ciphertext = transit.encrypt(payload)
        result = transit.decrypt(ciphertext)
        assert result == payload

    def test_roundtrip_nested(self):
        payload = {"DB_URL": "postgres://user:pass@host/db", "SECRET": "s3cr3t!"}
        assert transit.decrypt(transit.encrypt(payload)) == payload

    def test_encrypt_returns_str_when_url_safe(self):
        ct = transit.encrypt({"a": "b"}, url_safe=True)
        assert isinstance(ct, str)

    def test_encrypt_returns_bytes_when_not_url_safe(self):
        ct = transit.encrypt({"a": "b"}, url_safe=False)
        assert isinstance(ct, bytes)

    def test_decrypt_accepts_bytes(self):
        payload = {"x": "y"}
        ct_str = transit.encrypt(payload)
        ct_bytes = base64.b64decode(ct_str)
        assert transit.decrypt(ct_bytes) == payload

    def test_decrypt_wrong_ciphertext_raises(self):
        bad = base64.b64encode(b"\x00" * 40).decode()
        with pytest.raises(Exception):
            transit.decrypt(bad)

    def test_nonce_is_random_so_ciphertexts_differ(self):
        payload = {"k": "v"}
        ct1 = transit.encrypt(payload)
        ct2 = transit.encrypt(payload)
        assert ct1 != ct2  # nonces differ
