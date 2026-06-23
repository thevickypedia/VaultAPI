# Signature authentication

VaultAPI's signature authentication method is required for all API requests.

### Creating authorization header

VaultAPI expects authorization header to use the format below

```text
Authorization: Signature=sha512Hash,timestamp=UNIXTimestamp
```

Signature value is the unsalted SHA-512 hash of the concatenation of:
1. API key + UNIX timestamp in seconds (for `GET` and `POST` requests)
2. API key + shared secret + UNIX timestamp in seconds (for `DELETE` and `PATCH` requests)

Timestamp value must be the same value used to generate the signature.
If a different timestamp value is provided, VaultAPI will not be able to verify the signature hash value and the request will be rejected.

### Signature Generation code samples

#### Php

```php
$apiKey = "abcdefg";
$secret = "1a2bc3";
$timestamp = (string)time();
$token = $apiKey . '.' . $secret; // use $apiKey alone for GET/POST
$authHeader = 'Authorization: Signature=' . hash_hmac('sha512', $timestamp, $token) . ',timestamp=' . $timestamp;
```

#### JavaScript

```javascript
var crypto = require('crypto');
var apiKey = '123';
var secret = '123';
var timestamp = String(Math.floor(Date.now() / 1000));
var token = apiKey + '.' + secret; // use apiKey alone for GET/POST
var signature = crypto.createHmac('sha512', token).update(timestamp).digest('hex');
var authHeaderValue = 'Signature=' + signature + ',timestamp=' + timestamp;
```

#### Java

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
String apiKey = "123";
String secret = "123";
String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
String token = apiKey + "." + secret; // use apiKey alone for GET/POST
Mac mac = Mac.getInstance("HmacSHA512");
mac.init(new SecretKeySpec(token.getBytes("UTF-8"), "HmacSHA512"));
byte[] bytes = mac.doFinal(timestamp.getBytes("UTF-8"));
StringBuilder sb = new StringBuilder();
for (byte b : bytes) sb.append(String.format("%02x", b));
String authHeaderValue = "Signature=" + sb.toString() + ",timestamp=" + timestamp;
```

#### Python

```python
#!/usr/bin/env python
import hashlib
import hmac
import time
apiKey = "123"
secret = "123"
timestamp = str(int(time.time()))
token = f"{apiKey}.{secret}"  # use apiKey alone for GET/POST
signature = hmac.new(token.encode("utf-8"), timestamp.encode("utf-8"), hashlib.sha512).hexdigest()
authHeaderValue = f"Signature={signature},timestamp={timestamp}"
```

#### Ruby

```ruby
require 'openssl'
apiKey = "123"
secret = "123"
timestamp = Time.now.to_i.to_s
token = "#{apiKey}.#{secret}"  # use apiKey alone for GET/POST
signature = OpenSSL::HMAC.hexdigest('SHA512', token, timestamp)
authHeaderValue = "Signature=#{signature},timestamp=#{timestamp}"
```

#### C#

```csharp
using System.Security.Cryptography;
string apiKey = "123";
string secret = "123";
string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
string token = apiKey + "." + secret; // use apiKey alone for GET/POST
var keyBytes = System.Text.Encoding.UTF8.GetBytes(token);
var msgBytes = System.Text.Encoding.UTF8.GetBytes(timestamp);
using (var hmac = new HMACSHA512(keyBytes))
{
    var hashBytes = hmac.ComputeHash(msgBytes);
    var signature = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    var authHeaderValue = "Signature=" + signature + ",timestamp=" + timestamp;
}
```

#### Perl

```perl
use strict;
use Digest::HMAC_SHA512 qw(hmac_sha512_hex);
my $apiKey = '123';
my $secret = '123';
my $timestamp = time;
my $token = "$apiKey.$secret";  # use $apiKey alone for GET/POST
my $sig = hmac_sha512_hex($timestamp, $token);
my $authHeaderValue = "Signature=$sig,timestamp=$timestamp";
```

#### Go

```go
apiKey := "123"
secret := "123"
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
token := apiKey + "." + secret // use apiKey alone for GET/POST
mac := hmac.New(sha512.New, []byte(token))
mac.Write([]byte(timestamp))
signature := hex.EncodeToString(mac.Sum(nil))
authHeaderValue := "Signature=" + signature + ",timestamp=" + timestamp
```
