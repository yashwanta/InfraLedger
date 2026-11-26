import { schema, type Entity, type Item } from './model';

/** A record as returned by the API: typed core fields plus schema-defined extras. */
export type Rec = Item & { [key: string]: any };

let timeZone = 'America/New_York';
let csrfToken = '';
export const setTimeZone = (tz: string) => { if (tz) timeZone = tz; };
export const setCsrf = (token: string) => { csrfToken = token || ''; };

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

export async function api<T = any>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
    ...(data !== undefined ? { body: JSON.stringify(data) } : {}),
  });
  let body: any;
  try { body = await response.json(); } catch { throw new Error('Server returned an invalid response'); }
  if (!response.ok) {
    if (response.status === 401 && path === '/me') return null as T;
    throw new ApiError(body?.error || 'Request failed', response.status);
  }
  return body as T;
}

export function download(data: string, name: string, type = 'application/json') {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([data], { type }));
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export const initials = (s: unknown) => String(s || '').split(/\s+/).slice(0, 2).map(v => v[0] || '').join('').toUpperCase();
export const date = (s?: string) => s
  ? new Date(s.includes('T') ? s : s + 'T12:00:00Z').toLocaleDateString(undefined, { timeZone, month: 'short', day: 'numeric', year: 'numeric' })
  : '—';
export const when = (s: string) => new Date(s).toLocaleString(undefined, { timeZone });
export function days(s: string) {
  const today = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
  return Math.round((new Date(s + 'T12:00:00Z').getTime() - new Date(today + 'T12:00:00Z').getTime()) / 86400000);
}
export function money(v: unknown, currency = 'USD') {
  try { return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(Number(v) || 0); }
  catch { return `${currency} ${Number(v) || 0}`; }
}
export function tone(value: string) {
  if (/expired|revoked|overdue|retired|cancelled/i.test(value)) return 'red';
  if (/review|draft|submitted|pending|repair|progress|onboarding|reserved/i.test(value)) return 'warn';
  if (/ordered|dhcp|trial/i.test(value)) return 'blue';
  if (/inactive|not started/i.test(value)) return 'gray';
  return '';
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

/** Minimal Markdown renderer. All text is escaped before formatting, so the output is safe to inject. */
export function markdown(text: unknown) {
  const source = String(text || '').replace(/\r/g, '');
  let inCode = false, html = '', list = '';
  const endList = () => { if (list) { html += `</${list}>`; list = ''; } };
  for (const line of source.split('\n')) {
    if (line.startsWith('```')) { endList(); html += inCode ? '</code></pre>' : '<pre><code>'; inCode = !inCode; continue; }
    if (inCode) { html += esc(line) + '\n'; continue; }
    const safe = esc(line).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
    const h = /^(#{1,3}) (.*)/.exec(safe);
    if (h) { endList(); html += `<h${h[1].length}>${h[2]}</h${h[1].length}>`; continue; }
    const li = /^(?:[-*] |\d+\. )(.*)/.exec(safe);
    if (li) {
      const type = /^\d/.test(safe) ? 'ol' : 'ul';
      if (list !== type) { endList(); html += `<${type}>`; list = type; }
      html += `<li>${li[1]}</li>`;
    } else { endList(); if (safe.trim()) html += `<p>${safe}</p>`; }
  }
  endList();
  if (inCode) html += '</code></pre>';
  return html;
}

export function parseCSV(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [], value = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { if (quoted && text[i + 1] === '"') { value += '"'; i++; } else quoted = !quoted; }
    else if (c === ',' && !quoted) { row.push(value); value = ''; }
    else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(value); if (row.some(v => v.trim())) rows.push(row); row = []; value = '';
    } else value += c;
  }
  if (quoted) throw new Error('CSV contains an unclosed quoted field');
  row.push(value); if (row.some(v => v.trim())) rows.push(row);
  if (rows.length < 2) throw new Error('CSV needs a header and at least one data row');
  const headers = rows.shift()!.map(v => v.trim().replace(/^﻿/, ''));
  if (!headers.includes('name')) throw new Error('CSV must include a name column');
  if (new Set(headers).size !== headers.length) throw new Error('CSV headers must be unique');
  return rows.map((r, i) => {
    if (r.length !== headers.length) throw new Error(`Row ${i + 2} has a different number of columns`);
    return Object.fromEntries(headers.map((k, n) => [k, r[n].trim()]));
  });
}

export function exportCSV(type: Entity, rows: Rec[]) {
  const keys = ['name', 'orgId', ...(schema[type] || []).filter(f => !['password', 'steps', 'lines', 'textarea'].includes(f.kind)).map(f => f.key), 'notes'];
  // Quote every value and neutralise spreadsheet formula prefixes.
  const encode = (v: unknown) => '"' + String(v ?? '').replaceAll('"', '""') + '"';
  const safe = (v: unknown) => /^[=+@\-\t\r]/.test(String(v || '')) ? "'" + v : v;
  download([keys.map(encode).join(','), ...rows.map(r => keys.map(k => encode(safe(r[k]))).join(','))].join('\r\n'), `trinetra-${type}.csv`, 'text/csv;charset=utf-8');
}

export function generatePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';
  const bytes = new Uint8Array(80);
  crypto.getRandomValues(bytes);
  const limit = Math.floor(256 / alphabet.length) * alphabet.length; // rejection sampling avoids modulo bias
  return [...bytes].filter(n => n < limit).slice(0, 24).map(n => alphabet[n % alphabet.length]).join('');
}

export async function fileToBase64(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let start = 0; start < bytes.length; start += 8192) binary += String.fromCharCode(...bytes.subarray(start, start + 8192));
  return btoa(binary);
}

export const errorMessage = (e: unknown) => e instanceof Error ? e.message : String(e);
