# InfraLedger

**All your IT documentation in one secure, self-hosted place.**

InfraLedger keeps a complete, connected record of the IT you support, organized by client or organization:

- **Documentation:** knowledge base articles (Markdown, version history, review dates), runbooks with checklists, file attachments and team comments
- **Password vault:** credentials encrypted at rest, reveal requires re-authentication and is audited, TOTP codes for stored seeds
- **Inventory:** assets with lifecycle status, warranty, custom fields from templates, and device purchasing that receives orders straight into inventory
- **Infrastructure:** networks & IPAM with validation, IP addresses, ports & cabling, rack elevations, and drag-and-drop network diagrams linked to assets
- **Operations:** vendors, software licenses, domains, certificates, agreements, locations and contacts, with an Expirations page for everything due in 90 days
- **Management:** roles (admin, editor, viewer, client), per-organization access, MFA, audit log, recycle bin, CSV import/export, reports and a read-only API

Built with a **Go** backend (REST API, SQLite, AES-GCM vault) and a **React + TypeScript** frontend.

## Requirements

- Go 1.25+
- Node.js 22.5+ (for the frontend build and the API test suite, which uses `node:sqlite`)

## Build and run

```sh
npm install
npm run build             # React UI -> dist/
npm run build:server      # Go server -> outputs/infraledger.exe
outputs/infraledger.exe   # http://127.0.0.1:5173
```

Or, during development, run `npm start` (Go API on :5173) and `npm run dev` (Vite on :5175, proxying `/api` to the Go server).

On first visit you create the administrator account and can optionally load fictional sample records. The built-in user guide is added to the knowledge base automatically.

### Configuration

| Flag / env var | Default | Purpose |
| --- | --- | --- |
| `-addr` / `LISTEN_ADDR` | `127.0.0.1:5173` | HTTP listen address |
| `-data` / `DATA_DIR` | `data` | Database, vault key and attachments |
| `-static` / `STATIC_DIR` | `dist` | Built React UI |
| `APP_ORIGIN` | — | Allowed origin when served behind a proxy |
| `APP_TIMEZONE` | `America/New_York` | Time zone for due dates and expirations |
| `COOKIE_SECURE=1` | off | Mark session cookies `Secure` (set when serving over HTTPS) |
| `VAULT_KEY` | `data/vault.key` | Base64 32-byte vault key, instead of the key file |

Serve over HTTPS (for example behind a reverse proxy) for anything beyond local use.

## User guide

[`docs/kb/`](docs/kb) has a guide for every page of the app, starting with [Getting started](docs/kb/00-getting-started.md). The guides are compiled into the server and installed as knowledge base articles under the **InfraLedger Help** organization:

- automatically when a new workspace is created, and
- on demand from **Settings → Install / update user guide** (admins), which adds missing guides and restores edited ones to the shipped text as a new version. Your own articles are never changed.

To add or change a guide, edit the Markdown file (it must start with a `# Title` line), rebuild the server, and use the Settings button.

## Tests

```sh
npm test               # Go unit tests + full API suite against the Go server
npm run test:go-unit   # go test ./...
npm run test:api       # tests/app.test.mjs against a freshly built Go binary
```

`tests/harness.mjs` builds and starts the Go server for the API suite; set `INFRALEDGER_BIN` to reuse an existing build.

## Backup and recovery

The vault key encrypts every stored credential and MFA seed. **The database and the vault key must be backed up and restored together**; a database without its key cannot reveal secrets.

1. Stop the server so SQLite flushes its write-ahead log.
2. Copy the entire data directory (`infraledger.sqlite` with its `-wal` and `-shm` files, and `vault.key`).
3. Store the copy somewhere access-controlled; it contains encrypted secrets and the key to decrypt them.

To restore, stop the server, replace the data directory with the backup, and start it again. If you use `VAULT_KEY`, back up that value separately and keep it out of source control.

Workspaces created before the rename keep using their existing `trinetra.sqlite` file; no migration is needed.

The in-app **Export documentation** download is JSON without credentials, users or attachment contents. It is useful for migration, not as a full backup.
