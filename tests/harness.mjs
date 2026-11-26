// Starts the Go server for the API test suite behind a small interface:
//   createApp({dataDir}) -> { server: { listen(port, host, cb), address() }, db: { prepare(sql).get(...args) }, close() }
// The binary is built once into a temp directory unless TRINETRA_BIN points to an existing build.
import { spawn, execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), computed independently of the server. */
export function totp(seed, time = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of seed.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30000)));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = mac.at(-1) & 15;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}

let binary = process.env.TRINETRA_BIN;
function goBinary() {
  if (!binary) {
    binary = join(mkdtempSync(join(tmpdir(), 'trinetra-bin-')), process.platform === 'win32' ? 'trinetra.exe' : 'trinetra');
    execFileSync('go', ['build', '-o', binary, './cmd/trinetra'], { cwd: root, stdio: 'inherit' });
  }
  return binary;
}

const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

async function waitForReady(url, child, output) {
  for (let i = 0; i < 200; i++) {
    if (child.exitCode !== null) throw new Error(`Go server exited (${child.exitCode}):\n${output()}`);
    let status;
    try { const r = await fetch(url + '/api/status'); if (r.ok) status = await r.json(); } catch { /* not listening yet */ }
    if (status) {
      if (status.backend !== 'Go') throw new Error(`Expected the Go backend, got ${status.backend}`);
      return;
    }
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('Go server did not become ready:\n' + output());
}

export function createApp({ dataDir }) {
  let child, port;
  const app = {
    server: {
      listen(_port, host, callback) {
        (async () => {
          port = await freePort();
          let log = '';
          child = spawn(goBinary(), ['-addr', `${host}:${port}`, '-data', dataDir, '-static', join(root, 'dist')], { stdio: ['ignore', 'pipe', 'pipe'] });
          child.stdout.on('data', d => { log += d; });
          child.stderr.on('data', d => { log += d; });
          await waitForReady(`http://${host}:${port}`, child, () => log);
          callback();
        })().catch(error => { console.error(error); process.exitCode = 1; throw error; });
      },
      address: () => ({ port }),
    },
    // Read-only inspection of the Go server's SQLite database (WAL mode allows concurrent readers).
    db: {
      prepare(sql) {
        return {
          get(...args) {
            const db = new DatabaseSync(join(dataDir, 'trinetra.sqlite'), { readOnly: true });
            try { return db.prepare(sql).get(...args); } finally { db.close(); }
          },
        };
      },
    },
    close() {
      if (!child || child.exitCode !== null) return Promise.resolve();
      return new Promise(resolve => { child.once('exit', resolve); child.kill(); });
    },
  };
  return app;
}
