"""Tests for vaultapi/otp.py."""

import os

import pytest

pyotp = pytest.importorskip("pyotp")
qrcode = pytest.importorskip("qrcode")

from vaultapi.otp import OTPConfig, display_secret, generate_qr  # noqa: E402


class _FakeTOTP:
    def __init__(self, secret):
        self.secret = secret

    def provisioning_uri(self, name, issuer_name):
        return f"otpauth://totp/{issuer_name}:{name}?secret={self.secret}&issuer={issuer_name}"


class _FakeQR:
    def __init__(self):
        self.saved_as = None
        self.show_called = False

    def save(self, filename):
        self.saved_as = filename

    def show(self):
        self.show_called = True


def test_generate_qr_uses_default_filename_when_missing(monkeypatch):
    fake_qr = _FakeQR()

    monkeypatch.setattr(pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(pyotp, "TOTP", _FakeTOTP)
    monkeypatch.setattr(qrcode, "make", lambda _uri: fake_qr)
    monkeypatch.setattr("vaultapi.otp.display_secret", lambda *_args, **_kwargs: None)

    config = OTPConfig(
        qr_filename="",
        authenticator_user="user@example.com",
        authenticator_app="VaultAPI",
    )
    generate_qr(show_qr=False, config=config)

    assert fake_qr.saved_as == "otp_qr.png"
    assert config.qr_filename == "otp_qr.png"
    assert config.secret == "JBSWY3DPEHPK3PXP"


def test_generate_qr_keeps_custom_filename(monkeypatch):
    fake_qr = _FakeQR()

    monkeypatch.setattr(pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(pyotp, "TOTP", _FakeTOTP)
    monkeypatch.setattr(qrcode, "make", lambda _uri: fake_qr)
    monkeypatch.setattr("vaultapi.otp.display_secret", lambda *_args, **_kwargs: None)

    config = OTPConfig(
        qr_filename="custom.png",
        authenticator_user="user@example.com",
        authenticator_app="VaultAPI",
    )
    generate_qr(show_qr=False, config=config)

    assert fake_qr.saved_as == "custom.png"
    assert config.qr_filename == "custom.png"


def test_generate_qr_calls_show_when_enabled(monkeypatch):
    fake_qr = _FakeQR()

    monkeypatch.setattr(pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(pyotp, "TOTP", _FakeTOTP)
    monkeypatch.setattr(qrcode, "make", lambda _uri: fake_qr)
    monkeypatch.setattr("vaultapi.otp.display_secret", lambda *_args, **_kwargs: None)

    config = OTPConfig(
        qr_filename="custom.png",
        authenticator_user="user@example.com",
        authenticator_app="VaultAPI",
    )
    generate_qr(show_qr=True, config=config)

    assert fake_qr.show_called is True


def test_display_secret_uses_terminal_size(monkeypatch, capsys):
    config = OTPConfig(
        qr_filename="otp_qr.png",
        authenticator_user="user@example.com",
        authenticator_app="VaultAPI",
        secret="ABCDEF",
    )
    monkeypatch.setattr("vaultapi.otp.os.get_terminal_size", lambda: os.terminal_size((20, 20)))

    display_secret(config)
    out = capsys.readouterr().out

    assert "*" * 20 in out
    assert "Your TOTP secret key is: ABCDEF" in out


def test_display_secret_falls_back_when_terminal_size_unavailable(monkeypatch, capsys):
    config = OTPConfig(
        qr_filename="otp_qr.png",
        authenticator_user="user@example.com",
        authenticator_app="VaultAPI",
        secret="ABCDEF",
    )
    monkeypatch.setattr(
        "vaultapi.otp.os.get_terminal_size",
        lambda: (_ for _ in ()).throw(OSError("no tty")),
    )

    display_secret(config)
    out = capsys.readouterr().out

    assert "*" * 120 in out
    assert "QR code saved as 'otp_qr.png'" in out
