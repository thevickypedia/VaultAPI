"""Module that performs transit encryption/decryption.

This allows the server to securely transmit retrieved secrets to be decrypted
at the client side using the API key.
"""

import base64
import hashlib
import json
import secrets
import time
from typing import Any, ByteString, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import models


def string_to_aes_key(input_string: str, key_length: int) -> ByteString:
    """Derive an AES key from a string by SHA-256 hashing and truncating.

    See Also:
        AES supports three key lengths:
            - 128 bits (16 bytes)
            - 192 bits (24 bytes)
            - 256 bits (32 bytes)

    Args:
        input_string: Input string to hash.
        key_length: Number of bytes to take from the SHA-256 digest.

    Returns:
        ByteString:
        First ``key_length`` bytes of the SHA-256 digest of ``input_string``.
    """
    hash_object = hashlib.sha256(input_string.encode())
    return hash_object.digest()[:key_length]


def encrypt(payload: Dict[str, Any], url_safe: bool = True) -> ByteString | str:
    """Encrypt a payload dict using AES-GCM with a time-bucketed derived key.

    Args:
        payload: Dictionary to encrypt.
        url_safe: When ``True``, returns a Base64-encoded string; otherwise returns
            raw bytes.

    Returns:
        ByteString | str:
        Ciphertext as a URL-safe Base64 string when ``url_safe`` is ``True``,
        or raw bytes otherwise.
    """
    nonce = secrets.token_bytes(12)
    encoded = json.dumps(payload).encode()
    epoch = int(time.time()) // models.env.transit_time_bucket
    aes_key = string_to_aes_key(
        f"{epoch}.{models.env.apikey}.{models.env.secret}",
        models.env.transit_key_length,
    )
    ciphertext = nonce + AESGCM(aes_key).encrypt(nonce, encoded, b"")
    if url_safe:
        return base64.b64encode(ciphertext).decode("utf-8")
    return ciphertext


def decrypt(ciphertext: ByteString | str) -> Dict[str, Any]:
    """Decrypt AES-GCM ciphertext produced by ``encrypt``.

    Args:
        ciphertext: Base64-encoded string or raw bytes produced by ``encrypt``.

    Returns:
        Dict[str, Any]:
        Deserialized JSON payload.

    Raises:
        InvalidTag: If the ciphertext was produced with a different key or is corrupted.
    """
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    epoch = int(time.time()) // models.env.transit_time_bucket
    aes_key = string_to_aes_key(
        f"{epoch}.{models.env.apikey}.{models.env.secret}",
        models.env.transit_key_length,
    )
    decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
    return json.loads(decrypted)


if __name__ == "__main__":
    encrypted = encrypt({"key": "value"})
    b64_encoded = base64.b64encode(encrypted).decode("utf-8")
    print(decrypt(b64_encoded))
