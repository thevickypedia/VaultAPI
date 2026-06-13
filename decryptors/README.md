# Transit Protection

VaultAPI includes an added security feature that protects retrieved secrets during transit to the client.

1. Decrypts the requested secret values from the database (uses Fernet algorithm)
2. Constructs a payload with the requested key-value pairs.
3. Encrypts the payload with the API key, secret and a timestamp that's valid for 60s

### Other security recommendations

- Set `TRANSIT_KEY_LENGTH` to strong value (`16`/`24`/`32`...) to increase transit security.
- Set `TRANSIT_TIME_BUCKET` to a lower value to set the decryption timeframe to a minimum.

### Transit decryption logic in various languages

### Python

**Install requirements**
```shell
pip install requests cryptography
```

**Run decrypt**
```shell
python decrypt.py
```

### Go lang

**Run decrypt**
```shell
go run decrypt.go
```

### JavaScript

**Install requirements**
```shell
npm install axios
```

**Run decrypt**
```shell
node decrypt.js
```
