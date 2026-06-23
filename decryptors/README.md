# Transit Protection

VaultAPI includes an added security feature that protects retrieved secrets during transit to the client.

1. Decrypts the requested secret values from the database (uses Fernet algorithm)
2. Constructs a payload with the requested key-value pairs.
3. Encrypts the payload with the API key, secret and a timestamp that's valid for 60s

### API Authentication

All API requests require an HMAC-SHA512 time-based signature in the `Authorization` header:

```
Authorization: Bearer Signature=<hmac_sha512_hex>,timestamp=<unix_timestamp>
```

The signature is computed as,
- `HMAC-SHA512(key=apikey, msg=timestamp)` for `GET` and `POST` requests
- `HMAC-SHA512(key=apikey+secret, msg=timestamp)` for `PUT`, `DELETE`, and `PATCH` requests

`timestamp` is the current Unix time as an integer string.
The server rejects requests with timestamps older than 5 seconds or more than 1 second in the future.

> Refer [signature.md](signature.md) for code samples on how to generate the required signature header in various programming languages.

### Other security recommendations

- Set `TRANSIT_KEY_LENGTH` to strong value (`16`/`24`/`32`...) to increase transit security.
- Set `TRANSIT_TIME_BUCKET` to a lower value to set the decryption timeframe to a minimum.
