import { useEffect, useMemo, useRef, useState } from 'react';
import { names, schema, type Entity, type Field, type User } from './model';
import { api, date, errorMessage, fileToBase64, generatePassword, markdown, money, parseCSV, when, type Rec } from './lib';
import { useApp } from './ctx';
import { Act, Badge, Confirm, Icon, useSubmit } from './ui';
import { DiagramSvg } from './diagram';

const noOrg = (type: Entity) => ['organizations', 'vendors', 'templates'].includes(type);
const multi = (e: React.ChangeEvent<HTMLSelectElement>) => [...e.target.selectedOptions].map(o => o.value);

export function recordNoun(type: Entity) {
  return type === 'articles' ? 'article' : type === 'passwords' ? 'credential' : type === 'purchases' ? 'purchase order' : names[type].toLowerCase().replace(/s$/, '');
}

export function defaults(type: Entity): Partial<Rec> {
  if (type === 'racks') return { units: 42 };
  if (type === 'purchases') return { quantity: 1, unitCost: 0, currency: 'USD', status: 'Draft' };
  if (type === 'diagrams') return { nodes: [], edges: [] };
  return {};
}

/* ------------------------------------------------------------------ record form */

export function RecordForm({ type, record, onSaved }: { type: Entity; record: Partial<Rec>; onSaved: (r: Rec) => void }) {
  const app = useApp();
  const fields = schema[type];
  const editing = !!record.id;
  const [values, setValues] = useState<Record<string, any>>(() => {
    const v: Record<string, any> = { name: record.name || '', orgId: record.orgId || '', notes: record.notes || '', visibility: record.visibility === 'client' ? 'client' : 'internal' };
    for (const f of fields) {
      if (f.kind === 'steps') v[f.key] = (record.steps || []).map(s => s.text).join('\n');
      else if (f.kind === 'lines') v[f.key] = (record.fields || []).join('\n');
      else if (f.kind === 'password') v[f.key] = '';
      else if (f.kind === 'select') v[f.key] = record[f.key] ?? f.options![0];
      else v[f.key] = record[f.key] ?? '';
    }
    return v;
  });
  const [related, setRelated] = useState<string[]>(record.relatedIds || []);
  const [custom, setCustom] = useState<Record<string, string>>(record.customFields || {});
  const set = (key: string, value: any) => setValues(v => ({ ...v, [key]: value }));
  const template = app.byId(values.templateId);

  const changeOrg = (orgId: string) => setValues(v => {
    // Linked records must belong to the selected organization; clear links that no longer apply.
    const next: Record<string, any> = { ...v, orgId };
    for (const f of fields) if (f.kind === 'ref' && next[f.key] && app.byId(next[f.key])?.orgId && app.byId(next[f.key])!.orgId !== orgId) next[f.key] = '';
    setRelated(r => r.filter(id => app.byId(id)?.orgId === orgId));
    return next;
  });

  const { onSubmit, busy, error } = useSubmit(async () => {
    if (!noOrg(type) && !values.orgId) throw new Error('Select an organization');
    const body: Record<string, any> = { ...record, ...values, type, relatedIds: related };
    for (const f of fields) {
      if (f.kind === 'number' && values[f.key] !== '') body[f.key] = Number(values[f.key]);
      if (f.kind === 'password' && editing && !values[f.key]) delete body[f.key];
      if (f.kind === 'steps') body.steps = String(values.steps || '').split('\n').map(s => s.trim()).filter(Boolean)
        .map(text => ({ text, done: record.steps?.find(s => s.text === text)?.done || false }));
      if (f.kind === 'lines') body.fields = String(values.fields || '').split('\n').map(s => s.trim()).filter(Boolean);
    }
    if (type === 'passwords' && !editing && !body.password) throw new Error('Enter or generate a password');
    body.customFields = template ? Object.fromEntries((template.fields || []).map((n: string) => [n, custom[n] || ''])) : {};
    if (noOrg(type) && !values.orgId) delete body.orgId;
    const result = await api<Rec>('/records' + (editing ? '/' + record.id : ''), editing ? 'PUT' : 'POST', body);
    app.close();
    await app.reload();
    app.toast(editing ? 'Changes saved' : 'Record created');
    onSaved(result);
  });

  const control = (f: Field) => {
    const value = values[f.key] ?? '';
    const onChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => set(f.key, e.target.value);
    if (f.kind === 'ref') {
      const options = app.ofType(f.ref!).filter(v => !v.orgId || v.orgId === (values.orgId || app.scope));
      return <select name={f.key} required={f.required} value={value} onChange={onChange}>
        <option value="">Select {f.label.toLowerCase()}</option>
        {options.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>;
    }
    if (f.kind === 'select') return <select name={f.key} value={value} onChange={onChange}>{f.options!.map(o => <option key={o}>{o}</option>)}</select>;
    if (['textarea', 'steps', 'lines'].includes(f.kind))
      return <textarea name={f.key} required={f.required} style={f.key === 'content' ? { minHeight: 270 } : undefined} maxLength={30000} value={value} onChange={onChange} />;
    const input = <input name={f.key} type={f.kind} value={value} onChange={onChange} required={f.required && !(f.kind === 'password' && editing)}
      {...(f.kind === 'number' ? { min: 0, step: 'any' } : {})} maxLength={f.kind === 'password' ? 4096 : 1000}
      placeholder={f.placeholder || ''} autoComplete={f.kind === 'password' ? 'new-password' : undefined} />;
    if (f.key === 'password') return <div className="password-controls">{input}
      <button type="button" onClick={() => { set('password', generatePassword()); app.toast('Generated a 24-character password'); }}>Generate</button></div>;
    return input;
  };

  const relatable = app.records.filter(v => v.id !== record.id && v.type !== 'organizations' && v.orgId === values.orgId);
  return <form onSubmit={onSubmit}>
    <div className="form-grid">
      <label className="form-field">{type === 'articles' ? 'Article title' : 'Name'} *
        <input name="name" value={values.name} onChange={e => set('name', e.target.value)} required maxLength={200} /></label>
      {!noOrg(type) && <label className="form-field">Organization *
        <select name="orgId" required value={values.orgId} onChange={e => changeOrg(e.target.value)}>
          <option value="">Select organization</option>
          {app.ofType('organizations').map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
        </select></label>}
      {fields.map(f => <label key={f.key} className={`form-field ${f.full ? 'full' : ''}`}>{f.label}{f.required ? ' *' : ''}{control(f)}
        {f.kind === 'password' && editing && <small>Leave blank to keep the current value.</small>}</label>)}
      {template && <div className="full">
        <div className="form-section">{template.name} fields</div>
        <div className="form-grid" style={{ marginTop: 15 }}>
          {(template.fields || []).map((n: string) => <label key={n} className="form-field">{n}
            <input value={custom[n] || ''} maxLength={2000} onChange={e => setCustom(c => ({ ...c, [n]: e.target.value }))} /></label>)}
        </div></div>}
      {type !== 'passwords' && !noOrg(type) && <label className="form-field">Visibility
        <select name="visibility" value={values.visibility} onChange={e => set('visibility', e.target.value)}>
          <option value="internal">Internal only</option><option value="client">Client visible</option>
        </select><small>Client users see only assigned organizations.</small></label>}
      <label className="form-field full">Notes<textarea name="notes" maxLength={30000} value={values.notes} onChange={e => set('notes', e.target.value)} /></label>
      {type !== 'templates' && type !== 'vendors' && <label className="form-field full">Related records
        <select multiple aria-label="Related records" value={related} onChange={e => setRelated(multi(e))}>
          {relatable.map(v => <option key={v.id} value={v.id}>{names[v.type] + ' · ' + v.name}</option>)}
        </select><small>Hold Ctrl or Command to select multiple records.</small></label>}
    </div>
    {error}
    <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button>
      <button className="primary" type="submit" disabled={busy}>{editing ? 'Save changes' : 'Create record'}</button></div>
  </form>;
}

/* ------------------------------------------------------------------ record detail */

const linkKeys = ['rackId', 'assetId', 'connectedAssetId', 'networkId', 'locationId', 'purchaseId', 'templateId', 'vendorId'];

function Reveal({ id }: { id: string }) {
  const app = useApp();
  const [secret, setSecret] = useState<{ password: string; totp?: string; validFor?: number } | null>(null);
  const timer = useRef<number>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const { onSubmit, busy, error } = useSubmit(async (data, form) => {
    const result = await api(`/records/${id}/reveal`, 'POST', data);
    form.reset();
    setSecret(result);
    clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setSecret(null), 30000);
  });
  return <>
    <form onSubmit={onSubmit}>
      <div className="form-grid">
        <label className="form-field">Your account password<input name="password" type="password" required autoComplete="current-password" /></label>
        {app.user.mfa && <label className="form-field">Authenticator code<input name="code" required inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" /></label>}
      </div>
      {error}
      <div className="form-actions"><button type="submit" className="primary" disabled={busy}>Reveal credential</button></div>
    </form>
    {secret && <div className="secret">
      <div><code>{secret.password}</code><small>Automatically concealed in 30 seconds.</small>
        {secret.totp && <p style={{ margin: '10px 0 0' }}>Authenticator: <code>{secret.totp}</code><small>Valid for {secret.validFor} seconds.</small></p>}</div>
      <div className="actions">
        <Act onClick={async () => { await navigator.clipboard.writeText(secret.password); app.toast('Copied. Clipboard contents are managed by your operating system.'); }}>Copy</Act>
        <button onClick={() => { clearTimeout(timer.current); setSecret(null); }}>Hide</button>
      </div></div>}
  </>;
}

function Comments({ r, refresh }: { r: Rec; refresh: () => Promise<void> }) {
  const app = useApp();
  const { onSubmit, busy, error } = useSubmit(async (data, form) => {
    await api(`/records/${r.id}/comments`, 'POST', data);
    form.reset();
    await refresh();
    app.toast('Comment added');
  });
  return <div className="detail-section"><h3>Team comments</h3>
    {(r.comments || []).map(c => <div key={c.id} className="comment"><small>{c.author} · {when(c.created)}</small><p>{c.body}</p></div>)}
    {app.writable && <form className="comment-form" onSubmit={onSubmit}>
      <input name="body" required maxLength={5000} aria-label="Comment" placeholder="Add a note for your team…" />
      <button type="submit" disabled={busy}>Post comment</button>{error}</form>}
  </div>;
}

function Attachments({ r, refresh }: { r: Rec; refresh: () => Promise<void> }) {
  const app = useApp();
  const upload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target, file = input.files?.[0];
    if (!file) return;
    try {
      if (file.size > 5 * 1024 * 1024) throw new Error('File limit is 5 MB');
      await api(`/records/${r.id}/attachments`, 'POST', { name: file.name, mime: file.type, content: await fileToBase64(file) });
      await refresh();
      app.toast('Attachment uploaded');
    } catch (err) { app.toast(errorMessage(err)); }
    finally { input.value = ''; }
  };
  return <div className="detail-section"><h3>Attachments</h3>
    <div className="file-list">
      {(r.attachments || []).map(f => <span key={f.id} className="file-link">
        <a href={`/api/attachments/${f.id}`} download>{f.name}</a><small>{Math.ceil(f.size / 1024)} KB</small>
        {app.writable && <Act className="icon-button danger" aria-label="Delete attachment"
          onClick={async () => { await api('/attachments/' + f.id, 'DELETE', {}); await refresh(); app.toast('Attachment removed'); }}>×</Act>}
      </span>)}
      {!r.attachments?.length && <small>No attachments.</small>}
    </div>
    {app.writable && <label className="form-field" style={{ marginTop: 15 }}>Attach a file (up to 5 MB)<input type="file" onChange={upload} /></label>}
  </div>;
}

function Purchase({ r }: { r: Rec }) {
  const app = useApp();
  const next = ({ Draft: 'submit', Submitted: app.admin ? 'approve' : '', Approved: 'order', Ordered: 'receive' } as Record<string, string>)[r.status || ''];
  const labels: Record<string, string> = { submit: 'Submit for approval', approve: 'Approve order', order: 'Mark as ordered', receive: 'Receive devices into inventory' };
  const states: Record<string, string> = { submit: 'Submitted', approve: 'Approved', order: 'Ordered', cancel: 'Cancelled' };
  const confirm = (transition: string) => app.modal(transition === 'receive' ? 'Receive devices into inventory?' : 'Update purchase order?',
    <Confirm label={`Confirm ${transition === 'receive' ? 'receipt' : 'status'}`}
      text={transition === 'receive' ? `Create ${Number(r.quantity)} inventory devices linked to ${r.name}.` : `Mark ${r.name} as ${states[transition]}.`}
      notice={<div className="notice" style={{ marginTop: 20 }}>This records an internal workflow step. It does not send an order to a vendor or make a payment.</div>}
      onConfirm={async () => {
        await api(`/records/${r.id}/purchase`, 'POST', { action: transition, version: r.version });
        await app.reload();
        await app.openDetail(r.id);
        app.toast('Purchase order updated');
      }} />, 'small');
  return <>
    <div className="notice">Order total: <strong>{money(r.quantity * r.unitCost, r.currency)}</strong><br />Draft · Submitted · Approved · Ordered · Received</div>
    {app.writable && next && <button className="primary" onClick={() => confirm(next)}>{labels[next]}</button>}
    {app.writable && !['Received', 'Cancelled'].includes(r.status || '') && <> <button onClick={() => confirm('cancel')}>Cancel order</button></>}
    {!!r.receivedAssets?.length && <><h3 className="subheading">Received devices</h3>
      <div className="file-list">{r.receivedAssets.map((a: string) => <button key={a} onClick={() => app.openDetail(a)}>{app.title(a)}</button>)}</div></>}
  </>;
}

function Steps({ r, refresh }: { r: Rec; refresh: () => Promise<void> }) {
  const app = useApp();
  const steps = r.steps || [];
  const done = steps.filter(s => s.done).length;
  const toggle = async (index: number, checked: boolean) => {
    try {
      const next = structuredClone(steps);
      next[index].done = checked;
      await api('/records/' + r.id, 'PUT', { ...r, steps: next, status: next.every(s => s.done) ? 'Completed' : 'In progress' });
      await app.reload();
      await refresh();
    } catch (e) { app.toast(errorMessage(e)); }
  };
  return <>
    <div className="procedure-progress"><span>{done} / {steps.length} completed</span>
      <span className="bar"><i style={{ width: `${steps.length ? done / steps.length * 100 : 0}%` }} /></span></div>
    {steps.map((s, i) => <label key={i} className={`procedure-step ${s.done ? 'done' : ''}`}>
      <input type="checkbox" checked={s.done} disabled={!app.writable} onChange={e => toggle(i, e.target.checked)} /><span>{s.text}</span></label>)}
  </>;
}

export function Detail({ initial }: { initial: Rec }) {
  const app = useApp();
  const [r, setR] = useState(initial);
  const refresh = async () => setR(await api<Rec>('/records/' + r.id));
  const meta = (schema[r.type] || []).filter(f => !['password', 'textarea', 'steps', 'lines'].includes(f.kind) && r[f.key] !== undefined && r[f.key] !== '' && f.key !== 'templateId');
  const related = useMemo(() => app.records.filter(o => o.id !== r.id && ((r.relatedIds || []).includes(o.id) || (o.relatedIds || []).includes(r.id)
    || linkKeys.some(k => o[k] === r.id) || (r.type === 'organizations' && o.orgId === r.id))), [app.records, r]);
  const allocations = r.type === 'networks' ? app.ofType('addresses').filter(a => a.networkId === r.id) : [];

  const value = (f: Field) => {
    const v = r[f.key];
    if (f.kind === 'ref') return <button className="text-button" onClick={() => app.openDetail(v)}>{app.title(v)}</button>;
    if (f.kind === 'date') return date(v);
    if (f.kind === 'url' && /^https?:\/\//i.test(v)) return <a className="safe-link" href={v} target="_blank" rel="noopener noreferrer">{v}</a>;
    return String(v);
  };

  return <>
    <div className="actions">
      <Badge value={names[r.type]} />{r.status && <Badge value={r.status} />}
      {r.orgId && <button className="text-button" onClick={() => app.openDetail(r.orgId!)}>{app.title(r.orgId)}</button>}
      <Act className="text-button" onClick={async () => { await api(`/records/${r.id}/favorite`, 'POST', { active: !r.favorite }); await app.reload(); await refresh(); }}>
        <Icon name="favorites" />{r.favorite ? 'Favorited' : 'Favorite'}</Act>
      {app.writable && <button className="text-button" onClick={() => app.edit(r.type, r.id)}><Icon name="edit" />Edit</button>}
    </div>
    {r.type === 'passwords' && <>
      <div className="notice" style={{ marginTop: 20 }}>Password access requires reauthentication and is written to the audit log.</div>
      {app.writable ? <Reveal id={r.id} /> : <p className="muted">Your role cannot reveal vault secrets.</p>}
    </>}
    <div className="detail-meta">
      {meta.map(f => <div key={f.key}><small>{f.label}</small><strong>{value(f)}</strong></div>)}
      {Object.entries(r.customFields || {}).map(([k, v]) => <div key={k}><small>{k}</small><strong>{String(v)}</strong></div>)}
    </div>
    {r.type === 'articles' && <article className="article-content" dangerouslySetInnerHTML={{ __html: markdown(r.content) }} />}
    {r.type === 'procedures' && <Steps r={r} refresh={refresh} />}
    {r.type === 'templates' && <div className="notice">Custom fields: {(r.fields || []).join(', ')}</div>}
    {r.type === 'networks' && <div className="detail-section"><h3>IP allocations ({allocations.length})</h3>
      {allocations.map(a => <div key={a.id} className="mini-item"><span>{a.address} · {a.name}</span><button className="text-button" onClick={() => app.openDetail(a.id)}>Open</button></div>)}
      {!allocations.length && <p className="muted">No IP addresses allocated yet.</p>}
      {app.writable && <button onClick={() => app.edit('addresses', '', { orgId: r.orgId, networkId: r.id })}>Allocate IP address</button>}
    </div>}
    {r.type === 'purchases' && <Purchase r={r} />}
    {r.type === 'diagrams' && <><div className="diagram-preview"><DiagramSvg d={r as any} /></div>
      <button onClick={() => app.openDiagram(r.id)}>Open diagram editor</button></>}
    {r.type === 'racks' && <button onClick={() => { app.close(); app.navigate('racks'); }}>View rack elevation</button>}
    {r.notes && <div className="article-content" style={{ marginTop: 20 }} dangerouslySetInnerHTML={{ __html: markdown(r.notes) }} />}
    {!!related.length && <div className="detail-section"><h3>Linked documentation ({related.length})</h3>
      <div className="file-list">{related.map(o => <button key={o.id} onClick={() => app.openDetail(o.id)}><Icon name={o.type} />{o.name}</button>)}</div></div>}
    <Attachments r={r} refresh={refresh} />
    {app.user.role !== 'client' && <Comments r={r} refresh={refresh} />}
    <div className="form-actions">
      <small style={{ marginRight: 'auto' }}>Version {r.version} · Updated {when(r.updated)}</small>
      {r.type !== 'passwords' && app.user.role !== 'client' && <Act onClick={() => openHistory(app, r)}>Version history</Act>}
      {app.writable && <button className="danger" onClick={() => confirmDelete(app, r)}>Move to recycle bin</button>}
    </div>
  </>;
}

function confirmDelete(app: ReturnType<typeof useApp>, r: Rec) {
  app.modal('Move record to recycle bin?', <Confirm danger label="Move to recycle bin"
    text={`${r.name} can be restored later. Records with active links must be unlinked first.`}
    onConfirm={async () => { await api('/records/' + r.id, 'DELETE', {}); app.close(); await app.reload(); app.toast('Record moved to recycle bin'); }} />, 'small');
}

async function openHistory(app: ReturnType<typeof useApp>, r: Rec) {
  const versions = await api<{ version: number; actor: string; time: string; data: unknown }[]>('/records/' + r.id + '/versions');
  const canRevert = app.writable && !['passwords', 'purchases'].includes(r.type);
  app.modal('Version history — ' + r.name, <>{versions.map(v => <details key={v.version} className="version-item">
    <summary>Version {v.version} · {v.actor} · {when(v.time)}</summary>
    <pre>{JSON.stringify(v.data, null, 2)}</pre>
    {canRevert && v.version !== r.version && <Act onClick={async () => {
      await api(`/records/${r.id}/revert`, 'POST', { targetVersion: v.version, version: r.version });
      await app.reload();
      await app.openDetail(r.id);
      app.toast('Version restored as a new revision');
    }}>Restore this version</Act>}
  </details>)}</>);
}

/* ------------------------------------------------------------------ CSV import */

export function ImportForm({ type }: { type: Entity }) {
  const app = useApp();
  const [csv, setCsv] = useState('');
  const [orgId, setOrgId] = useState(app.scope);
  const keys = ['name', ...(schema[type] || []).filter(f => !['ref', 'password', 'steps', 'lines'].includes(f.kind)).map(f => f.key)];
  const { onSubmit, busy, error } = useSubmit(async () => {
    const parsed: Record<string, any>[] = parseCSV(csv).map(r => ({ ...r, type, orgId }));
    if (type === 'procedures') for (const r of parsed) r.steps = String(r.steps || '').split('|').filter(Boolean).map(text => ({ text, done: false }));
    const result = await api<{ records: Rec[] }>('/import', 'POST', { records: parsed });
    app.close();
    await app.reload();
    app.toast(`${result.records.length} records imported`);
  });
  const readFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) { app.toast('CSV file limit is 5 MB'); return; }
    setCsv(await f.text());
  };
  return <form onSubmit={onSubmit}>
    <label className="form-field">Organization<select required value={orgId} onChange={e => setOrgId(e.target.value)}>
      <option value="">Select organization</option>{app.ofType('organizations').map(o => <option key={o.id} value={o.id}>{o.name}</option>)}</select></label>
    <p className="import-help">CSV columns use field keys. Required: name, plus required fields for this record type. Linked fields must use record IDs. Up to 500 records; the entire import is validated before saving.</p>
    <div className="code-block">{keys.join(',')}</div>
    <label className="form-field" style={{ marginTop: 15 }}>Choose CSV file<input type="file" accept=".csv,text/csv" onChange={readFile} /></label>
    <label className="form-field" style={{ marginTop: 15 }}>Or paste CSV<textarea required style={{ minHeight: 180 }} value={csv} onChange={e => setCsv(e.target.value)} /></label>
    {error}
    <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button><button className="primary" type="submit" disabled={busy}>Validate and import</button></div>
  </form>;
}

/* ------------------------------------------------------------------ users, tokens, account */

export function UserForm({ existing, onSaved }: { existing?: User; onSaved: () => void }) {
  const app = useApp();
  const [orgs, setOrgs] = useState<string[]>(existing?.orgs || []);
  const { onSubmit, busy, error } = useSubmit(async data => {
    const id = existing?.id;
    await api('/users' + (id ? '/' + id : ''), id ? 'PUT' : 'POST', { ...data, active: data.active === 'true', orgs });
    app.close();
    onSaved();
    app.toast('User access saved');
  });
  return <form onSubmit={onSubmit}>
    <div className="form-grid">
      {!existing && <>
        <label className="form-field">Full name<input name="name" required maxLength={120} /></label>
        <label className="form-field">Email<input name="email" type="email" required /></label>
        <label className="form-field full">Initial password<input name="password" type="password" required minLength={12} maxLength={256} autoComplete="new-password" />
          <small>Share through a secure channel. The user can change it in Settings.</small></label>
      </>}
      <label className="form-field">Role<select name="role" defaultValue={existing?.role || 'editor'}>{['editor', 'viewer', 'client', 'admin'].map(r => <option key={r}>{r}</option>)}</select></label>
      {existing && <label className="form-field">Account status<select name="active" defaultValue={String(existing.active)}>
        <option value="true">Active</option><option value="false">Disabled</option></select></label>}
      <label className="form-field full">Assigned organizations<select multiple value={orgs} onChange={e => setOrgs(multi(e))}>
        {app.ofType('organizations').map(o => <option key={o.id} value={o.id}>{o.name}</option>)}</select>
        <small>Empty means all organizations for editors/viewers. Clients require at least one. Administrators always have full access. Hold Ctrl/Command for multiple selections.</small></label>
    </div>
    {error}
    <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button><button type="submit" className="primary" disabled={busy}>{existing ? 'Save access' : 'Create user'}</button></div>
  </form>;
}

export function Tokens() {
  const app = useApp();
  const [rows, setRows] = useState<{ id: string; name: string; expires: string }[] | null>(null);
  const [created, setCreated] = useState<{ token: string; expires: string } | null>(null);
  const load = () => api('/tokens').then(setRows).catch(e => app.toast(errorMessage(e)));
  useEffect(() => { load(); }, []);
  const { onSubmit, busy, error } = useSubmit(async (data, form) => { setCreated(await api('/tokens', 'POST', data)); form.reset(); });
  if (created) return <>
    <div className="notice warning">Copy this token now. It will not be displayed again. Keep it out of documentation records and source code.</div>
    <div className="code-block">{created.token}</div><small>Expires {when(created.expires)}</small>
    <div className="form-actions"><button onClick={() => { setCreated(null); load(); }}>Back to token list</button><button className="primary" onClick={app.close}>Done</button></div>
  </>;
  return <>
    <div className="notice">Tokens expire after 30 days and cannot reveal credentials or change data.</div>
    {rows === null ? <p className="muted">Loading…</p> : rows.map(t => <div key={t.id} className="mini-item">
      <div><strong>{t.name}</strong><small>Expires {when(t.expires)}</small></div>
      <Act onClick={async () => { await api('/tokens/' + t.id, 'DELETE', {}); await load(); app.toast('API token revoked'); }}>Revoke</Act></div>)}
    <form className="comment-form" style={{ marginTop: 20 }} onSubmit={onSubmit}>
      <input name="name" required aria-label="Token name" placeholder="Integration name" /><button type="submit" className="primary" disabled={busy}>Create token</button>{error}
    </form>
  </>;
}

export function PasswordForm({ onChanged }: { onChanged: (result: { user: User; csrf: string }) => void }) {
  const app = useApp();
  const { onSubmit, busy, error } = useSubmit(async data => {
    if (data.password !== data.confirm) throw new Error('New passwords do not match');
    onChanged(await api('/password', 'POST', data));
    app.close();
    app.toast('Password changed; other sessions signed out');
  });
  return <form onSubmit={onSubmit}>
    <div className="form-grid">
      <label className="form-field full">Current password<input name="current" type="password" required autoComplete="current-password" /></label>
      <label className="form-field full">New password<input name="password" type="password" required minLength={12} maxLength={256} autoComplete="new-password" /></label>
      <label className="form-field full">Confirm new password<input name="confirm" type="password" required minLength={12} autoComplete="new-password" /></label>
    </div>
    {error}
    <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button><button className="primary" type="submit" disabled={busy}>Change password</button></div>
  </form>;
}

export function MfaForm() {
  const app = useApp();
  const enabled = app.user.mfa;
  const [seed, setSeed] = useState('');
  const finish = async (message: string) => { app.setUser((await api('/me')).user); app.close(); app.toast(message); };
  const step1 = useSubmit(async (data, form) => {
    if (enabled) { await api('/mfa/disable', 'POST', data); await finish('MFA disabled'); return; }
    setSeed((await api('/mfa/start', 'POST', data)).seed); form.reset();
  });
  const step2 = useSubmit(async data => { await api('/mfa/confirm', 'POST', data); await finish('MFA enabled'); });
  if (seed) return <>
    <div className="notice">In your authenticator app, add an account using a setup key. Choose time-based (TOTP), 6 digits, and a 30-second period. Keep this key private.</div>
    <label className="form-field">Setup key<div className="code-block" style={{ marginTop: 8 }}>{seed}</div></label>
    <form style={{ marginTop: 20 }} onSubmit={step2.onSubmit}>
      <label className="form-field">Six-digit code<input name="code" required inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" /></label>
      {step2.error}
      <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button><button className="primary" type="submit" disabled={step2.busy}>Enable MFA</button></div>
    </form>
  </>;
  return <form onSubmit={step1.onSubmit}>
    <label className="form-field">Your account password<input name="password" type="password" required autoComplete="current-password" /></label>
    {enabled && <label className="form-field" style={{ marginTop: 15 }}>Current authenticator code<input name="code" required inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" /></label>}
    {step1.error}
    <div className="form-actions"><button type="button" onClick={app.close}>Cancel</button><button className="primary" type="submit" disabled={step1.busy}>{enabled ? 'Disable MFA' : 'Continue'}</button></div>
  </form>;
}
