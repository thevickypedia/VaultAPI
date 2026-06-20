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
    """Displays the TOTP secret key."""
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
    """Generates a QR code for TOTP setup.

    Args:
        - show_qr: If True, displays the QR code using the default image viewer.
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
