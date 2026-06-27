"""OTP module that handles TOTP secret generation, QR code creation, and secret display."""

import os
from dataclasses import dataclass

import pyotp
import qrcode


@dataclass
class OTPConfig:
    """Data class to hold OTP configuration.

    >>> OTPConfig

    """

    qr_filename: str
    authenticator_user: str
    authenticator_app: str
    secret: str = ""


def display_secret(config: OTPConfig) -> None:
    """Print the TOTP secret key and QR code filename to the terminal.

    Args:
        config: OTP configuration containing the secret and QR filename to display.
    """
    try:
        term_size = os.get_terminal_size().columns
    except OSError:
        term_size = 120
    base = "*" * term_size
    print(
        f"\n{base}\n"
        f"\nYour TOTP secret key is: {config.secret}"
        f"\nQR code saved as {config.qr_filename!r} (you can scan this with your authenticator app).\n"
        f"\n{base}",
    )


def generate_qr(show_qr: bool, config: OTPConfig) -> None:
    """Generate a TOTP secret, create a QR code, and optionally display it.

    See Also:
        Steps performed:
        1. Generate a new Base32 TOTP secret.
        2. Build a ``otpauth://`` provisioning URI for authenticator apps.
        3. Render the URI as a QR code and save it to ``config.qr_filename``.
        4. Update ``config.secret`` with the generated secret.
        5. Print the secret to the terminal via ``display_secret``.

    Args:
        show_qr: If ``True``, opens the QR code image with the default viewer.
        config: OTP configuration updated in-place with the generated secret and filename.
    """
    # STEP 1: Generate a new secret key for the user (store this securely!)
    secret = pyotp.random_base32()

    # STEP 2: Create a provisioning URI (for the QR code)
    uri = pyotp.TOTP(secret).provisioning_uri(name=str(config.authenticator_user), issuer_name=config.authenticator_app)

    # STEP 3: Generate a QR code (scan this with your authenticator app)
    qr = qrcode.make(uri)
    if show_qr:
        qr.show()

    # Save the QR code
    qr_filename = config.qr_filename or "otp_qr.png"
    qr.save(qr_filename)
    config.qr_filename = qr_filename

    # STEP 4: Update the config with the new secret
    config.secret = secret
    display_secret(config)
