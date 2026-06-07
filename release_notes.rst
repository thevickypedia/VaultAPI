Release Notes
=============

v0.3.41a0 (06/07/2026)
----------------------
- `754a7c3 <https://github.com/thevickypedia/VaultAPI/commit/754a7c373341c672d8258de703436853b0470da0>`_ chore: Release ``v0.3.41a0``
- `4726ede <https://github.com/thevickypedia/VaultAPI/commit/4726edeb612cc5ab64e5902f0f637c57bc963bd1>`_ ci: Create/update GHA workflows to release and publish automatically

v0.3.4 (06/23/2025)
-------------------
- Allow dot env files with different name prefixes
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.3.3...v0.3.4

v0.3.3 (01/21/2025)
-------------------
- Includes a new API endpoint to delete existing tables
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.3.2...v0.3.3

v0.3.2 (01/19/2025)
-------------------
- Includes exception handlers to avoid the possibility of an ``Internal Server Error``
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.3.1...v0.3.2

v0.3.1 (01/19/2025)
-------------------
- Removes redundant ``GET`` and ``PUT`` secret functions
- Includes an option to enable transit encryption for ingress request
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.3.0...v0.3.1

v0.3.0 (01/19/2025)
-------------------
- Includes a feature to allow private IP, private IP range, and public IP address
- **Full Changelog**: https://github.com/thevickypedia/VaultAPI/compare/v0.2.1...v0.3.0

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
