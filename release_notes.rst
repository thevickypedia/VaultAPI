Release Notes
=============

v0.2.1 (01/18/2025)
-------------------
- Includes startup validations for ``transit_key_length`` and ``transit_time_bucket``
- Bug fix for docker entrypoint
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.2.0...v0.2.1

v0.2.0 (01/18/2025)
-------------------
- Improves transit security, **requiring** both APIKey and Secret to decrypt
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.1.1...v0.2.0

v0.1.1 (01/13/2025)
-------------------
- Includes a new API endpoint to list all secrets
- Fix a bug that prevented routes from loading when more than 1 worker was specified
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.1.0...v0.1.1

v0.1.0 (09/19/2024)
-------------------
- Includes a new feature to enable transit encryption
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.0.1...v0.1.0

v0.0.1 (09/18/2024)
-------------------
- Includes a feature to whitelist origins and IP addresses (including multiple IP ranges)
- Improved data structure for rate limiting
- Includes an endpoint to ``PUT`` multiple secrets at once
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.0.0...v0.0.1

v0.0.0 (09/17/2024)
-------------------
- Lightweight API to store/retrieve secrets to/from an encrypted Database

v0.0.0-a (08/23/2024)
---------------------
- Release alpha version to pypi
