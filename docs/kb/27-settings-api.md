# User guide — Settings & API

Manage your account security, API access and exports.

## Your account

- **Change password:** enter your current password and a new one of at least 12 characters. Your other sessions are signed out.
- **Authenticator MFA:** select **Set up authenticator**, confirm your password, add the setup key to an authenticator app (time-based, 6 digits, 30 seconds) and enter a code to enable it. Once enabled, sign-in and vault reveals require a code.

## Documentation export

Select **Export documentation** to download records as JSON. Credentials, user accounts and attachment contents are excluded. This is for migration, not a full backup.

## Read-only API

Admins can select **Manage API tokens** to create a token. Copy it immediately; it is shown only once and expires after 30 days. Tokens can read records and exports but cannot change data or reveal secrets.

```
GET /api/records?type=assets
Authorization: Bearer <token>
```

## User guide

Admins can select **Install / update user guide** to add or refresh these guides in the knowledge base.

## Backups

Stop the server and back up the whole data directory. The database and the vault key must be restored together.
