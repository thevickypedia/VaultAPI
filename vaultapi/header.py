import binascii
import hashlib
import hmac
import logging
import os
import time

LOGGER = logging.getLogger("uvicorn.default")

authorization = lambda token, skew=0: f"{token}.{int(time.time() // 5) - skew}"


def generate_signed_token(value: str):
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', value.encode('utf-8'), salt, 100_000)
    # Combine salt and hash, then convert to hex string
    return binascii.hexlify(salt + pw_hash).decode('utf-8')


def verify_signed_token(
    received_hash: str,
    candidate_token: str,
):
    print(f"Value sent by client: {received_hash}")
    print(f"Server generated: {candidate_token}")
    try:
        stored_bytes = binascii.unhexlify(received_hash)
    except binascii.Error as error:
        LOGGER.error(error)
        return False
    salt = stored_bytes[:16]
    stored_hash = stored_bytes[16:]
    pw_hash = hashlib.pbkdf2_hmac('sha256', candidate_token.encode('utf-8'), salt, 100_000)
    signature_verification = hmac.compare_digest(stored_hash, pw_hash)
    LOGGER.info(f"Signature verification: {signature_verification}")
    return signature_verification


def generate(token: str):
    prepared = authorization(token)
    return generate_signed_token(prepared)


def verify(token: str, received_hex: str):
    canonical_token = authorization(token)
    # Allows 1s for clock skew tolerance
    skew_tolerant_token = authorization(token, skew=1)
    return (
            verify_signed_token(received_hex, canonical_token) or
            verify_signed_token(received_hex, skew_tolerant_token)
    )
