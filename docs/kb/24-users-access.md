# User guide — Users & access

Admins control who can sign in and what they can see.

## Add a user

1. Select **Add user**.
2. Enter the name, email and an initial password of at least 12 characters. Share it through a secure channel; the user can change it in Settings.
3. Choose the role and assigned organizations, then select **Create user**.

## Roles

- **Admin:** everything, including users, API tokens and the audit log. Always has access to all organizations.
- **Editor:** creates and edits records and can reveal vault secrets. No assigned organizations means all organizations.
- **Viewer:** read-only access; cannot reveal secrets.
- **Client:** requires at least one assigned organization, and sees only records marked **Client visible** there.

## Change access

Select **Edit access** to change a user's role, organizations or status. Choose **Disabled** to block sign-in without deleting the account.
