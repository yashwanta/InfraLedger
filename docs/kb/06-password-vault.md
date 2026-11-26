# User guide — Password vault

The vault stores credentials encrypted at rest and links them to the systems they unlock.

## Add a credential

1. Select **Add credential** and choose the organization.
2. Enter a name, username, password and login URL. Select **Generate** for a random 24-character password.
3. Optionally add a TOTP seed (for accounts protected by an authenticator) and a rotation due date.
4. Link related assets under **Related records**, then select **Create record**.

## Reveal a password

1. Open the credential.
2. Enter **your own account password** (and your authenticator code if MFA is on).
3. Select **Reveal credential**. The password, and a current TOTP code if a seed is stored, are shown for 30 seconds, then hidden again.

## Security

- Every reveal is written to the audit log.
- Viewers and clients cannot reveal secrets, and API tokens can never reveal them.
- When editing, leave the password blank to keep the current value.
- Passwords are excluded from exports and cannot be imported from CSV.
- Rotation due dates appear on the Expirations page.
