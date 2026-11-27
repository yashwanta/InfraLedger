// Builds internal/app/oui.txt.gz, the MAC-prefix → manufacturer table used to
// label discovered devices, from the IEEE MA-L registry CSV.
//
// Refresh occasionally:
//   curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
//   node scripts/oui.mjs oui.csv
import fs from 'node:fs';
import zlib from 'node:zlib';

const src = process.argv[2];
if (!src) { console.error('usage: node scripts/oui.mjs <oui.csv>'); process.exit(1); }

function parseLine(line) {
  const out = []; let cur = '', quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') quoted = false; else cur += c; }
    else if (c === '"') quoted = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur); return out;
}

const rows = new Map();
for (const line of fs.readFileSync(src, 'utf8').split(/\r?\n/).slice(1)) {
  if (!line.trim()) continue;
  const [registry, prefix, name] = parseLine(line);
  if (registry !== 'MA-L' || !/^[0-9A-F]{6}$/.test(prefix)) continue;
  const vendor = name.replace(/\s+/g, ' ').trim();
  if (vendor && vendor.toLowerCase() !== 'private') rows.set(prefix, vendor);
}
const text = [...rows].sort(([a], [b]) => a.localeCompare(b)).map(([p, v]) => p + '\t' + v).join('\n') + '\n';
const out = new URL('../internal/app/oui.txt.gz', import.meta.url);
fs.writeFileSync(out, zlib.gzipSync(text, { level: 9 }));
console.log(`${rows.size} manufacturer prefixes written to internal/app/oui.txt.gz`);
