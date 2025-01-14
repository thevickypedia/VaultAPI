import base64
import hashlib
import json
import os
import time
from typing import Any, ByteString, Dict

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APIKEY = os.environ["APIKEY"]
SECRET = os.environ["SECRET"]

TRANSIT_TIME_BUCKET = os.environ.get("TRANSIT_TIME_BUCKET", 60)
TRANSIT_KEY_LENGTH = os.environ.get("TRANSIT_KEY_LENGTH", 60)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = os.environ.get("PORT", 8080)


def transit_decrypt(ciphertext: str | ByteString) -> Dict[str, Any]:
    """Decrypt transit encrypted payload."""
    epoch = int(time.time()) // TRANSIT_TIME_BUCKET
    hash_object = hashlib.sha256(f"{epoch}.{APIKEY}.{SECRET}".encode())
    aes_key = hash_object.digest()[:TRANSIT_KEY_LENGTH]
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
    return json.loads(decrypted)


def get_cipher() -> str:
    """Get ciphertext from the server."""
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {APIKEY}",
    }
    params = {
        "table_name": "default",
    }
    response = requests.get(
        f"http://{HOST}:{PORT}/get-table",  # noqa: HttpUrlsUsage
        params=params,
        headers=headers,
    )
    assert response.ok, response.text
    return response.json()["detail"]


print(transit_decrypt(ciphertext=get_cipher()))
