# Trinetra IT Documentation

Self-hosted IT documentation: organizations, asset inventory, encrypted password vault, networks & IPAM, racks, diagrams, knowledge base, runbooks, purchasing, renewals, users/roles, audit log and a read-only API.

- **Backend:** Go (`cmd/trinetra`, `internal/app`) — REST API under `/api`, SQLite storage, AES-GCM vault.
- **Frontend:** React + TypeScript (`web/src`), built by Vite into `dist/` and served by the Go server.

## Requirements

- Go 1.25+
- Node.js 22.5+ (for the frontend build and the API test suite, which uses `node:sqlite`)

## Build and run

```sh
npm install
npm run build          # React UI -> dist/
npm run build:server   # Go server -> outputs/trinetra.exe
outputs/trinetra.exe   # http://127.0.0.1:5173
```

Or, during development, run `npm start` (Go API on :5173) and `npm run dev` (Vite on :5175, proxying `/api` to the Go server).

On first visit you create the administrator account and can optionally load fictional sample records.

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

## Tests

```sh
npm test               # Go unit tests + full API suite against the Go server
npm run test:go-unit   # go test ./...
npm run test:go        # tests/app.test.mjs against a freshly built Go binary
npm run test:api       # the same suite against the legacy Node server (server.mjs)
```

`tests/harness.mjs` starts either backend behind one interface; set `TRINETRA_BIN` to reuse an existing Go build.

## Backup and recovery

The vault key encrypts every stored credential and MFA seed. **The database and the vault key must be backed up and restored together** — a database without its key cannot reveal secrets.

1. Stop the server so SQLite flushes its write-ahead log.
2. Copy the entire data directory (`trinetra.sqlite`, `trinetra.sqlite-wal`, `trinetra.sqlite-shm`, `vault.key`).
3. Store the copy somewhere access-controlled; it contains encrypted secrets and the key to decrypt them.

To restore, stop the server, replace the data directory with the backup, and start it again. If you use `VAULT_KEY`, back up that value separately and keep it out of source control.

The in-app **Export documentation** download is JSON without credentials, users or attachment contents — useful for migration, not a full backup.

## Legacy files

`server.mjs` and `public/` are the original Node.js backend and vanilla-JS UI that the Go + React version replaces. They are kept only so the test suite can still compare both backends.
