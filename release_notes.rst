Release Notes
=============

v0.5.1 (06/13/2026)
-------------------
- `527da4f <https://github.com/thevickypedia/VaultAPI/commit/527da4fb5365c637b2f637bedb2936a413186f6c>`_ chore: Release ``v0.5.1``
- `782411f <https://github.com/thevickypedia/VaultAPI/commit/782411f26992803b66737aa046e2c4d20aa354cf>`_ style: Update error message for too many failed attempts in the UI
- `ab88806 <https://github.com/thevickypedia/VaultAPI/commit/ab8880683a28246015b0d479c32e8da9bdb55ef7>`_ refactor: Restructure server import and update database path handling
- `6207742 <https://github.com/thevickypedia/VaultAPI/commit/6207742fda7c2434666650f1fd8b1822e781c65a>`_ feat: Reset the lockout timer while maintaining the failed authentication count in the auth DB for tier-based escalation
- `24d3455 <https://github.com/thevickypedia/VaultAPI/commit/24d3455e2cd4bdff032f8df2c425236360cfede9>`_ chore: Update release notes for v0.5.0

v0.5.0 (06/10/2026)
-------------------
- `3cb27da <https://github.com/thevickypedia/VaultAPI/commit/3cb27dabafae6a78cb49a1afc4260b74811210d4>`_ chore: Release ``v0.5.0``
- `868fbfc <https://github.com/thevickypedia/VaultAPI/commit/868fbfc4dbe517695f040252981ee1a76711eb2d>`_ lint: Run linter and update docstrings
- `6e68ba0 <https://github.com/thevickypedia/VaultAPI/commit/6e68ba06f6179a35f0830e161f5d2ea0916f4f74>`_ fix: Reinstate accidentally removed fernet object during instantiation
- `46a55fe <https://github.com/thevickypedia/VaultAPI/commit/46a55fee03fd76d788afa9dd391e73f999d39ad8>`_ refactor: Remove cursor object for all DB operations
- `1c58eaa <https://github.com/thevickypedia/VaultAPI/commit/1c58eaa0c8b918514aa2b848a12b0effe3f8b730>`_ refactor: Change ``COOLOFF_THRESHOLDS`` to ``OrderedDict`` and update docstrings
- `a04495e <https://github.com/thevickypedia/VaultAPI/commit/a04495ee8050e4fd0d1a7115f144e3a1afc71f90>`_ refactor: Move all authentication/authorization functions to ``auth`` module
- `c72bb45 <https://github.com/thevickypedia/VaultAPI/commit/c72bb457b1559db5652196741dfbfc77155d16fd>`_ feat: Add brute-force protection using ``auth.db``
- `0117ce9 <https://github.com/thevickypedia/VaultAPI/commit/0117ce99e44554aaabd0ae982832fe30231dcf90>`_ perf: Remove IP based access controls and restricted allow listing protocol
- `e340b42 <https://github.com/thevickypedia/VaultAPI/commit/e340b425484486c035295d03724edeed2f9a560a>`_ lint: Refactor UI template
- `40a74af <https://github.com/thevickypedia/VaultAPI/commit/40a74afddb0b18f99b52e5efdf3b25b6e681fe93>`_ style: Add ``favicon.ico`` and ``apple-touch-icon``
- `f6e0efb <https://github.com/thevickypedia/VaultAPI/commit/f6e0efbfb986ce74db7323630daf32205d39c4df>`_ style: Update SVG logo in the UI login page
- `4eeeba7 <https://github.com/thevickypedia/VaultAPI/commit/4eeeba7599bf34de45da13ced4feea7ea3129fdc>`_ perf: Require ``secret`` value to login to the UI
- `e9ef7c3 <https://github.com/thevickypedia/VaultAPI/commit/e9ef7c357078f56862b35f8ea3bce750bda5a036>`_ perf: Replace in-memory session handler with a database table to solve secondary uvicorn workers missing auth tokens in-memory
- `2c3a59e <https://github.com/thevickypedia/VaultAPI/commit/2c3a59efb74dfaa3b2ecd5d891d12a07f913f249>`_ feat: Logout clears the token at server side to prevent unauthorized access
- `2d7f34e <https://github.com/thevickypedia/VaultAPI/commit/2d7f34ee5f8bfc82222f5b222d7c5af20c35e7c9>`_ revert: JWT implementation for UI authorization since the tokens can't be tracked without extra overhead
- `d297dd7 <https://github.com/thevickypedia/VaultAPI/commit/d297dd7b57b1be9e3ef3fe996ffbc79023e00a40>`_ feat: Implement JWT authorization for the UI
- `96d7c46 <https://github.com/thevickypedia/VaultAPI/commit/96d7c46efff08ca5379dbf2e7d47bb9ece935d57>`_ feat: Implement a TOTP check for `DELETE /ui/*` requests
- `9395935 <https://github.com/thevickypedia/VaultAPI/commit/939593531a72c6b3bac66e34619522353a1796c4>`_ chore: Update release notes for v0.4.0

v0.4.0 (06/08/2026)
-------------------
- `83eb494 <https://github.com/thevickypedia/VaultAPI/commit/83eb494b342a52fbe3a30d4313eb528e1ceb2da5>`_ chore: Release ``v0.4.0``
- `342ab11 <https://github.com/thevickypedia/VaultAPI/commit/342ab11cd1f5fd2e10f0b24e072da83786197559>`_ test: Update unit tests to meet 100% code coverage
- `6fae0ba <https://github.com/thevickypedia/VaultAPI/commit/6fae0ba6171826c2a6ea3a61e4d23bf4fd5c8268>`_ refactor: Add more logging for login errors
- `fb5c77e <https://github.com/thevickypedia/VaultAPI/commit/fb5c77e5b3f1b8c4af0ee3b3d4ad5ba477102d50>`_ style: Fix background attachment and set focus to totp when login fails
- `0cf99e6 <https://github.com/thevickypedia/VaultAPI/commit/0cf99e68415202dec66ec8cc2c7320d5fdb9393e>`_ perf: Monitor upstream ``url.hostname`` instead of ``client.host`` for rate limiting and IP based access controls
- `be80a8b <https://github.com/thevickypedia/VaultAPI/commit/be80a8ba1bf048b667bbe4da2205c11b2eb16ca9>`_ fix: Add missing dependencies
- `62ae30f <https://github.com/thevickypedia/VaultAPI/commit/62ae30f0bbc5be81adbe2139665d1d75a9c1e720>`_ test: Add unit tests for uncovered sections of otp.py
- `20174c2 <https://github.com/thevickypedia/VaultAPI/commit/20174c22b3c4989dd0334dc55a512e545b6f59a4>`_ fix: Address an edge case scenario for missing QR filename and update unit tests
- `81a10ec <https://github.com/thevickypedia/VaultAPI/commit/81a10ec38bdb980819ba83385b4cdd0e4a1d8f97>`_ feat: Include a util script to generate TOTP token and QR
- `823959d <https://github.com/thevickypedia/VaultAPI/commit/823959d5d18ec53b29d24ab7a156e6fa55e60dd2>`_ fix: Fix invalid filepath and project name/description for GHA
- `c9c2855 <https://github.com/thevickypedia/VaultAPI/commit/c9c2855a1a88626ab7a0b07866313f110979ca9e>`_ docs: Update GHA workflow reference links
- `4b956a2 <https://github.com/thevickypedia/VaultAPI/commit/4b956a2105e8d854c89f596f129b3853241740c2>`_ ci: Create new / update all GHA workflows
- `ef82cf7 <https://github.com/thevickypedia/VaultAPI/commit/ef82cf75953059839532934d7cb3363caf473ee0>`_ test: Limit the ignore list codes for flake8
- `7c8ef80 <https://github.com/thevickypedia/VaultAPI/commit/7c8ef80e155bf9a0a8661d40c3fe3a6f0bf3d789>`_ test: Update tests and pre-commit run
- `e555b1d <https://github.com/thevickypedia/VaultAPI/commit/e555b1da866bae2d9b927ffdbc9f841f8171db30>`_ test: Add unit tests with code coverage
- `8645570 <https://github.com/thevickypedia/VaultAPI/commit/864557086c40d9ed1f515ff241365e8112b8796c>`_ chore: Raise a startup error when ``pyotp`` is not installed
- `b6c03fa <https://github.com/thevickypedia/VaultAPI/commit/b6c03fa38c125c51c17780b52cb7f3e2fc023985>`_ docs: Run linter and update runbook
- `e90d3d4 <https://github.com/thevickypedia/VaultAPI/commit/e90d3d426bc777135f31e6d430c02ff19d23016d>`_ feat: Include an option in the UI to import bulk secrets
- `d531d51 <https://github.com/thevickypedia/VaultAPI/commit/d531d5107f882580feada7b9387136778fd19236>`_ perf: Handle session lifetime on client side
- `b00fd98 <https://github.com/thevickypedia/VaultAPI/commit/b00fd983c7e04cf05f9dbd24c308107f06ff7f05>`_ perf: Handle session lifetime on server side
- `79266fa <https://github.com/thevickypedia/VaultAPI/commit/79266fada32363b178c8cea9aef1fe0d815479dc>`_ fix: Show login screen only when session_token is invalid/expired
- `caee0de <https://github.com/thevickypedia/VaultAPI/commit/caee0ded89dc0aeef88b3c19cf227ce51ff927b4>`_ perf: Replace in-memory token handling with session storage
- `0041e09 <https://github.com/thevickypedia/VaultAPI/commit/0041e09e55342245c251b1ffd3607d7ff1161163>`_ perf: Change UI rendered to use Jinja templating
- `cded83e <https://github.com/thevickypedia/VaultAPI/commit/cded83ec14f4cb016c384b45245d98c08f377664>`_ lint: Run linter
- `d069fbf <https://github.com/thevickypedia/VaultAPI/commit/d069fbfb1245e2406145c9a13d4389122f504b56>`_ perf: Implement a dedicated session token for UI management
- `8fc6e6d <https://github.com/thevickypedia/VaultAPI/commit/8fc6e6d684bbd6d7d4b3128770f44d7ec5367bd8>`_ feat: Implement a login based UI with in-house auth mechanism
- `5e98d9a <https://github.com/thevickypedia/VaultAPI/commit/5e98d9a0ec959532517f8ec9c42c78ca585731a9>`_ feat: Create a base UI for VaultAPI
- `a68faa5 <https://github.com/thevickypedia/VaultAPI/commit/a68faa56cb0bccd97c8204c4c067e6a96916f7e3>`_ chore: Update requirements
- `0dff4a6 <https://github.com/thevickypedia/VaultAPI/commit/0dff4a6541dec21f8952a0727f7dfb306c84eaa0>`_ Update release notes

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
