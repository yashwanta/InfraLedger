import { useEffect, useState, type ReactNode } from 'react';
import { columns, names, schema, subtitles, type Entity, type User } from './model';
import { api, date, days, download, errorMessage, exportCSV, initials, money, when, type Rec } from './lib';
import { useApp, type AppCtx } from './ctx';
import { Act, AddButton, Badge, Empty, Heading, Icon, PanelHead, Stat, ViewLink, recordProps } from './ui';
import { DiagramSvg } from './diagram';
import { ImportForm, MfaForm, PasswordForm, Tokens, UserForm } from './dialogs';

const PAGE_SIZE = 30;
const coreTypes = ['assets', 'articles', 'passwords', 'networks', 'contacts'];

function coverage(app: AppCtx, org: Rec) {
  const linked = app.records.filter(r => r.orgId === org.id);
  return Math.round(coreTypes.filter(t => linked.some(r => r.type === t)).length / coreTypes.length * 100);
}
const remaining = (d: string, suffix = ' remaining') => days(d) < 0 ? `${Math.abs(days(d))} days overdue` : `${days(d)} days${suffix}`;

function OrganizationTable({ rows }: { rows: Rec[] }) {
  const app = useApp();
  return <div className="table-scroll"><table>
    <thead><tr><th>Organization</th><th>Assets</th><th>Coverage</th><th>Status</th></tr></thead>
    <tbody>{rows.map(o => {
      const pct = coverage(app, o);
      return <tr key={o.id} {...recordProps(app, o.id)}>
        <td><div className="record-name"><span className="initials">{initials(o.name)}</span><div><strong>{o.name}</strong><small>{o.domain || 'Organization'}</small></div></div></td>
        <td>{app.records.filter(r => r.orgId === o.id && r.type === 'assets').length}</td>
        <td><div className="coverage"><span className="bar"><i style={{ width: `${pct}%` }} /></span>{pct}%</div></td>
        <td><Badge value={o.status} /></td>
      </tr>;
    })}</tbody>
  </table></div>;
}

/* ------------------------------------------------------------------ overview */

export function Dashboard() {
  const app = useApp();
  const scoped = app.records.filter(app.inScope);
  const orgs = app.ofType('organizations').filter(app.inScope);
  const health = orgs.length ? Math.round(orgs.reduce((n, o) => n + coverage(app, o), 0) / orgs.length) : 0;
  const renewals = app.expirations();
  const articles = scoped.filter(r => r.type === 'articles');
  const diagram = app.ofType('diagrams').filter(app.inScope)[0];
  const quick = ([['assets', 'Add device'], ['articles', 'Write an article'], ['networks', 'Document network'], ['purchases', 'Create purchase order']] as [Entity, string][])
    .filter(([t]) => app.user.role !== 'client' || t === 'articles');
  return <>
    <Heading title="Workspace overview" sub={subtitles.dashboard}><AddButton type="articles" label="Create new" /></Heading>
    <div className="hero"><div><span className="eyebrow">A CLEARER PICTURE OF YOUR IT</span><h2>Everything connected. Nothing overlooked.</h2>
      <p>Your devices, networks, credentials, and team knowledge — organized around the organizations you support.</p></div>
      <button onClick={() => app.navigate('diagrams')}><Icon name="diagrams" />Explore your infrastructure</button></div>
    <div className="stats">
      <Stat label="Organizations" value={orgs.length} type="organizations" note="Client environments, connected" />
      <Stat label="Documented assets" value={scoped.filter(r => r.type === 'assets').length} type="assets" note="Inventory across your workspace" />
      <Stat label="Knowledge articles" value={articles.length} type="articles" note="Answers for your entire team" />
      <Stat label="Upcoming expirations" value={renewals.length} type="renewals" note="Due or overdue within 90 days" />
    </div>
    <div className="dashboard-grid">
      <div>
        <div className="panel"><PanelHead title="Your organizations"><ViewLink page="organizations" /></PanelHead>
          {orgs.length ? <OrganizationTable rows={orgs.slice(0, 5)} /> : <Empty title="Start with an organization" description="Build your documentation around the clients you support." type="organizations" />}
          <div className="table-foot"><span>{orgs.length} organizations in this view</span><span>Coverage across 5 core documentation types</span></div></div>
        <div className="panel"><PanelHead title="Quick actions" />
          <div className="quick-actions">{quick.map(([t, label]) =>
            <button key={t} onClick={() => app.writable ? app.edit(t) : app.navigate(t)}><Icon name={t} />{label}</button>)}</div></div>
        <div className="panel"><PanelHead title="Recently updated documentation"><ViewLink page="articles" /></PanelHead>
          {articles.length ? <div className="mini-list">{articles.slice(0, 4).map(r => <div key={r.id} className="mini-item">
            <span className="mini-icon"><Icon name="articles" /></span>
            <div><strong>{r.name}</strong><small>{app.title(r.orgId)} · {date(r.updated)}</small></div>
            <button className="text-button" onClick={() => app.openDetail(r.id)}>Open</button></div>)}</div>
            : <Empty title="No articles yet" description="Document a process or troubleshooting guide." type="articles" />}</div>
      </div>
      <div className="right-column">
        <div className="panel"><PanelHead title="Documentation coverage" />
          <div className="health"><div className="health-ring" style={{ '--progress': `${health}%` } as React.CSSProperties}><div><strong>{health}%</strong><small>Overall coverage</small></div></div>
            <div className="health-copy"><strong>{health >= 80 ? 'Well documented' : health ? 'Room to grow' : 'Start documenting'}</strong><p>Connect assets, networks,<br />contacts, articles, and credentials.</p></div></div>
          <div className="panel-note">Calculated from records in each organization</div></div>
        <div className="panel"><PanelHead title="Expirations & reviews"><ViewLink page="renewals" /></PanelHead>
          <div className="mini-list">{renewals.slice(0, 4).map(v => <div key={v.r.id + v.kind} className="mini-item">
            <span className="mini-icon"><Icon name={v.r.type} /></span>
            <div><strong>{v.r.name}</strong><small>{app.title(v.r.orgId)}</small><Badge value={remaining(v.date)} /></div>
            <button className="text-button" aria-label={`Open ${v.r.name}`} onClick={() => app.openDetail(v.r.id)}>⋯</button></div>)}
            {!renewals.length && <p className="muted" style={{ fontSize: 13, padding: '10px 0' }}>No upcoming expirations.</p>}</div></div>
        <div className="panel"><PanelHead title="Connected infrastructure"><ViewLink page="diagrams" /></PanelHead>
          {diagram ? <><div className="diagram-preview"><DiagramSvg d={diagram as any} /></div><div className="panel-note">{diagram.name}</div></>
            : <Empty title="Map your network" description="Create diagrams with linked inventory devices." type="diagrams" />}</div>
      </div>
    </div>
  </>;
}

/* ------------------------------------------------------------------ record lists */

function Cell({ r, k }: { r: Rec; k: string }) {
  const app = useApp();
  const v = r[k];
  if (k === 'status') return <Badge value={v} />;
  if (k.endsWith('Id')) return <>{app.title(v)}</>;
  if (['expires', 'purchaseDate', 'reviewDate'].includes(k)) return <>{date(v)}</>;
  if (k === 'total') return <>{money(r.quantity * r.unitCost, r.currency)}</>;
  if (k === 'fieldCount') return <>{r.fields?.length || 0}</>;
  if (k === 'completion') return <>{(r.steps || []).filter(s => s.done).length} / {(r.steps || []).length} steps</>;
  return <>{v === undefined || v === '' || v === null ? '—' : String(v)}</>;
}

function Pagination({ total, page, pages, setPage }: { total: number; page: number; pages: number; setPage: (n: number) => void }) {
  return <div className="table-foot"><span>{total} records · Page {page} of {pages}</span>
    <div className="table-pagination"><button disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button>
      <button disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button></div></div>;
}

const addLabel = (t: Entity) => ({ organizations: 'Add organization', articles: 'New article', passwords: 'Add credential', purchases: 'New purchase order' } as Record<string, string>)[t] || 'Add record';

export function ListPage({ type }: { type: Entity }) {
  const app = useApp();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const all = app.ofType(type);
  const rows = all.filter(app.inScope)
    .filter(r => !query || JSON.stringify(r).toLowerCase().includes(query.toLowerCase()))
    .filter(r => !filter || r.status === filter);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const visible = rows.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const statuses = [...new Set(all.map(r => r.status).filter(Boolean))] as string[];
  const cols = columns[type] || [];

  const openImport = () => {
    if (['organizations', 'templates', 'passwords'].includes(type)) {
      app.modal('CSV import', <><p className="subtitle">Create organizations and templates using their forms. CSV import is available for organization-owned asset, network, contact, and documentation records.</p>
        <div className="form-actions"><button onClick={app.close}>Got it</button></div></>, 'small');
      return;
    }
    app.modal('Import ' + names[type].toLowerCase(), <ImportForm type={type} />);
  };

  const tools = <div className="table-tools">
    <input aria-label="Search records" placeholder={`Search ${names[type].toLowerCase()}…`} value={query} onChange={e => { setQuery(e.target.value); setPage(1); }} />
    <div className="actions">
      {!!statuses.length && <select aria-label="Filter by status" value={filter} onChange={e => { setFilter(e.target.value); setPage(1); }}>
        <option value="">All statuses</option>{statuses.map(s => <option key={s}>{s}</option>)}</select>}
      <span className="muted" style={{ fontSize: 12 }}>{rows.length} records</span>
    </div></div>;

  const pager = <Pagination total={rows.length} page={current} pages={pages} setPage={setPage} />;
  const header = <>
    <Heading title={names[type]} sub={subtitles[type] || `Manage ${names[type].toLowerCase()} and their linked documentation.`}>
      {app.writable && type !== 'passwords' && <button onClick={openImport}><Icon name="download" />Import CSV</button>}
      <button onClick={() => exportCSV(type, rows)}><Icon name="download" />Export</button>
      <AddButton type={type} label={addLabel(type)} />
    </Heading>
    {type === 'passwords' && <div className="notice">Vault secrets are encrypted at rest. Revealing a credential requires your account password and authenticator code if MFA is enabled. Secret access is audited.</div>}
  </>;

  if (type === 'articles') return <>
    {header}
    <div className="panel"><PanelHead title="Articles"><span className="muted" style={{ fontSize: 12 }}>Markdown · History · Attachments</span></PanelHead>{tools}</div>
    {visible.length ? <div className="cards">{visible.map(r => <article key={r.id} className="doc-card" {...recordProps(app, r.id)}>
      <div className="card-meta"><Icon name={type} /><Badge value={r.status} /></div>
      <h3>{r.name}</h3><p>{String(r.content || r.notes || '').replace(/[#*`]/g, '').slice(0, 150)}…</p>
      <small>{app.title(r.orgId)} · {r.category || 'General'}</small></article>)}</div>
      : <Empty title="No matching articles" description="Try a different search, or create a new article." type={type} />}
    {pager}
  </>;

  return <>
    {header}
    <div className="panel"><PanelHead title={names[type]} />{tools}
      {!rows.length ? <Empty title={query ? 'No matching records' : 'No records yet'} description="Create a record to get started." type={type} />
        : type === 'organizations' ? <OrganizationTable rows={visible} />
          : <div className="table-scroll"><table>
            <thead><tr><th>Name</th>{!app.scope && <th>Organization</th>}{cols.map(([, label]) => <th key={label}>{label}</th>)}<th>Updated</th></tr></thead>
            <tbody>{visible.map(r => <tr key={r.id} {...recordProps(app, r.id)}>
              <td><strong>{r.name}</strong>{type === 'passwords' && <small>••••••••••••</small>}</td>
              {!app.scope && <td>{app.title(r.orgId)}</td>}
              {cols.map(([k]) => <td key={k}><Cell r={r} k={k} /></td>)}
              <td>{date(r.updated)}</td></tr>)}</tbody>
          </table></div>}
      {pager}</div>
  </>;
}

/* ------------------------------------------------------------------ expirations, racks, reports */

export function Expirations() {
  const app = useApp();
  const [query, setQuery] = useState('');
  const rows = app.expirations().filter(v => !query || (v.r.name + ' ' + app.title(v.r.orgId)).toLowerCase().includes(query.toLowerCase()));
  return <>
    <Heading title="Expirations & reviews" sub={subtitles.renewals} />
    <div className="panel"><PanelHead title="Next 90 days & overdue records" />
      <div className="table-tools"><input aria-label="Search records" placeholder="Search expirations…" value={query} onChange={e => setQuery(e.target.value)} /></div>
      <div className="table-scroll"><table>
        <thead><tr><th>Record</th><th>Organization</th><th>Category</th><th>Due date</th><th>Time remaining</th></tr></thead>
        <tbody>{rows.map(v => <tr key={v.r.id + v.kind} {...recordProps(app, v.r.id)}>
          <td><strong>{v.r.name}</strong></td><td>{app.title(v.r.orgId)}</td><td>{names[v.r.type]} · {v.kind}</td>
          <td>{date(v.date)}</td><td><Badge value={remaining(v.date, '')} /></td></tr>)}</tbody>
      </table></div>
      {!rows.length && <Empty title="No records due soon" description="Expiration dates and review dates will appear here." />}
    </div>
  </>;
}

export function Racks() {
  const app = useApp();
  const racks = app.ofType('racks').filter(app.inScope);
  return <>
    <Heading title="Rack management" sub={subtitles.racks}><AddButton type="racks" label="Add rack" /></Heading>
    {racks.length ? <div className="rack-grid">{racks.map(r => {
      const units = Number(r.units);
      const assets = app.ofType('assets').filter(a => a.rackId === r.id);
      const used = assets.reduce((n, a) => n + Number(a.rackUnits), 0);
      return <section key={r.id} className="rack-card">
        <div className="rack-title"><div><h3>{r.name}</h3><small>{app.title(r.orgId)} · {app.title(r.locationId)}</small></div>
          <button className="icon-button" aria-label="Rack details" onClick={() => app.openDetail(r.id)}><Icon name="edit" /></button></div>
        <div className="rack" style={{ gridTemplateRows: `repeat(${units},24px)` }}>
          {Array.from({ length: units }, (_, n) => [
            <span key={'u' + n} className="rack-unit" style={{ gridRow: n + 1 }}>{units - n}</span>,
            <span key={'s' + n} className="rack-slot" style={{ gridRow: n + 1 }} />])}
          {assets.map(a => {
            const start = Number(a.rackStart), height = Number(a.rackUnits);
            return <button key={a.id} className={`rack-device ${a.category === 'Server' ? 'server' : a.category === 'Firewall' ? 'firewall' : ''}`}
              style={{ gridRow: `${units - start - height + 2}/span ${height}` }} title={`${a.name} · U${start}–${start + height - 1}`} onClick={() => app.openDetail(a.id)}>
              <span>{a.name}</span><span className="lights">•••</span></button>;
          })}
        </div>
        <div className="rack-foot"><span>{used} / {units} U occupied</span><span>{Math.round(used / units * 100)}% utilization</span></div>
        {app.writable && <button className="text-button" style={{ marginTop: 12, fontSize: 12 }} onClick={() => app.edit('assets', '', { orgId: r.orgId, rackId: r.id, rackUnits: 1 })}>+ Place a device</button>}
      </section>;
    })}</div> : <Empty title="Create your first rack" description="Place inventory devices in rack units with overlap validation." type="racks" />}
  </>;
}

function Chart({ title, groups, total }: { title: string; groups: Record<string, number>; total: number }) {
  const entries = Object.entries(groups);
  return <div className="panel"><h2>{title}</h2>
    {entries.map(([k, v]) => <div key={k}><div className="report-line"><span>{k}</span><b>{v}</b></div>
      <div className="progress-line"><i style={{ width: `${total ? v / total * 100 : 0}%` }} /></div></div>)}
    {!entries.length && <p className="muted">No records yet.</p>}</div>;
}

export function Reports() {
  const app = useApp();
  const scoped = app.records.filter(app.inScope);
  const assets = scoped.filter(r => r.type === 'assets');
  const groupBy = (rows: Rec[], key: string) => rows.reduce<Record<string, number>>((a, r) => { const k = r[key] || 'Unspecified'; a[k] = (a[k] || 0) + 1; return a; }, {});
  const byOrg = Object.fromEntries(scoped.filter(r => r.type === 'organizations').map(o => [o.name, scoped.filter(r => r.orgId === o.id).length]));
  const exportReport = () => download(JSON.stringify({
    generatedAt: new Date().toISOString(), organization: app.scope || 'all',
    assets: app.ofType('assets').filter(app.inScope), purchases: app.ofType('purchases').filter(app.inScope),
    expirations: app.expirations().map(v => ({ name: v.r.name, org: app.title(v.r.orgId), type: v.kind, due: v.date, days: days(v.date) })),
  }, null, 2), 'trinetra-report.json');
  return <>
    <Heading title="Documentation & operations reports" sub={subtitles.reports}><button onClick={exportReport}><Icon name="download" />Export report</button></Heading>
    <div className="stats">
      <Stat label="Inventory value" value={money(assets.reduce((n, a) => n + Number(a.cost || 0), 0))} type="assets" note="Recorded costs · see currency per device" />
      <Stat label="Open purchase orders" value={scoped.filter(r => r.type === 'purchases' && !['Received', 'Cancelled'].includes(r.status || '')).length} type="purchases" note="Draft through ordered" />
      <Stat label="Articles needing review" value={scoped.filter(r => r.type === 'articles' && r.reviewDate && days(r.reviewDate) <= 0).length} type="articles" note="Review dates today or overdue" />
      <Stat label="License seats available" value={scoped.filter(r => r.type === 'licenses').reduce((n, r) => n + Math.max(0, Number(r.quantity || 0) - Number(r.assigned || 0)), 0)} type="licenses" note="Purchased less assigned seats" />
    </div>
    <div className="report-grid">
      <Chart title="Asset lifecycle" groups={groupBy(assets, 'status')} total={assets.length} />
      <Chart title="Inventory by device type" groups={groupBy(assets, 'category')} total={assets.length} />
      <Chart title="Records by organization" groups={byOrg} total={scoped.length} />
      <div className="panel"><h2>Rack utilization</h2>
        {scoped.filter(r => r.type === 'racks').map(r => {
          const used = assets.filter(a => a.rackId === r.id).reduce((n, a) => n + Number(a.rackUnits), 0);
          return <div key={r.id}><div className="report-line"><span>{r.name}</span><b>{used} / {r.units} U</b></div>
            <div className="progress-line"><i style={{ width: `${used / Number(r.units) * 100}%` }} /></div></div>;
        })}
        {!scoped.some(r => r.type === 'racks') && <p className="muted">No racks documented.</p>}</div>
    </div>
  </>;
}

/* ------------------------------------------------------------------ settings, favorites, trash */

export function Settings({ onPasswordChanged }: { onPasswordChanged: (r: { user: User; csrf: string }) => void }) {
  const app = useApp();
  const u = app.user;
  return <>
    <Heading title="Settings & integrations" sub="Manage account security, API access, and documentation exports." />
    <div className="settings-grid">
      <div className="panel"><h2>Your account</h2><p>{u.name}<br />{u.email}<br />{u.role} access</p>
        <button onClick={() => app.modal('Change your password', <PasswordForm onChanged={onPasswordChanged} />, 'small')}>Change password</button>
        <h3 style={{ marginTop: 25 }}>Authenticator MFA</h3>
        <p>{u.mfa ? 'MFA is enabled for your account.' : 'Add a six-digit authenticator code to protect sign-in and vault access.'}</p>
        <button onClick={() => app.modal(u.mfa ? 'Disable authenticator MFA' : 'Set up authenticator MFA', <MfaForm />, 'small')}>{u.mfa ? 'Disable MFA' : 'Set up authenticator'}</button></div>
      <div className="panel"><h2>Documentation export</h2>
        <p>Download organization documentation as JSON. Credentials, user accounts, and file attachment contents are excluded. Use a server backup for complete recovery.</p>
        {u.role !== 'client' && <Act onClick={async () => { download(JSON.stringify(await api('/export'), null, 2), 'trinetra-documentation.json'); app.toast('Documentation exported; credentials excluded'); }}>
          <Icon name="download" />Export documentation</Act>}
        <h3 style={{ marginTop: 25 }}>Server backups</h3>
        <p>Stop the server, then back up the complete data directory. The database and vault key must be restored together. See README for commands and recovery guidance.</p></div>
      {app.admin && <div className="panel"><h2>Read-only API access</h2>
        <p>Create a revocable, 30-day API token to read documentation from external tools. Secrets cannot be revealed through API tokens.</p>
        <button onClick={() => app.modal('Read-only API tokens', <Tokens />)}>Manage API tokens</button>
        <div className="code-block" style={{ marginTop: 18 }}>GET /api/records?type=assets<br />Authorization: Bearer &lt;token&gt;</div></div>}
      <div className="panel"><h2>Integration boundaries</h2>
        <p>CSV import/export and a read-only JSON API are available. Vendor-specific PSA/RMM/cloud synchronization, discovery agents, automated live certificate checks, SSO, browser extensions, and email delivery are not connected in this release.</p>
        <p>Expirations use the dates you document. Network maps show saved documentation, not live network discovery.</p></div>
    </div>
  </>;
}

export function Favorites() {
  const app = useApp();
  const rows = app.favorites.filter(app.inScope);
  return <>
    <Heading title="Favorites" sub="Keep your most useful documentation close." />
    <div className="cards">{rows.map(r => <article key={r.id} className="doc-card" {...recordProps(app, r.id)}>
      <Icon name={r.type} /><h3>{r.name}</h3><small>{names[r.type]} · {app.title(r.orgId)}</small></article>)}
      {!rows.length && <Empty title="No favorites yet" description="Open a record and select Favorite." />}</div>
  </>;
}

/** Loads page data from the API and re-fetches when `version` changes. */
function useRemote<T>(path: string, version: unknown): [T | null, string, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    api<T>(path).then(d => { if (live) { setData(d); setError(''); } }).catch(e => { if (live) setError(errorMessage(e)); });
    return () => { live = false; };
  }, [path, version, tick]);
  return [data, error, () => setTick(t => t + 1)];
}

function Remote<T>({ state, children }: { state: [T | null, string, () => void]; children: (data: T) => ReactNode }) {
  const [data, error] = state;
  if (error) return <Empty title={error} />;
  if (!data) return <p className="muted">Loading…</p>;
  return <>{children(data)}</>;
}

export function Trash() {
  const app = useApp();
  const state = useRemote<Rec[]>('/trash', app.records);
  return <>
    <Heading title="Recycle bin" sub="Restore deleted records. Linked records are validated before recovery." />
    <Remote state={state}>{rows => <div className="panel"><div className="mini-list">
      {rows.map(r => <div key={r.id} className="mini-item"><div><strong>{r.name}</strong><small>{names[r.type]} · {when(r.deleted)}</small></div>
        <Act onClick={async () => { await api(`/records/${r.id}/restore`, 'POST', {}); await app.reload(); app.toast('Record restored'); }}>Restore</Act></div>)}
      {!rows.length && <Empty title="Recycle bin is empty" />}
    </div></div>}</Remote>
  </>;
}

export function Users() {
  const app = useApp();
  const state = useRemote<User[]>('/users', null);
  const reload = state[2];
  if (!app.admin) return <Empty title="Administrator access required" />;
  return <>
    <Heading title="Users & access" sub="Control workspace roles and organization-level access.">
      <button className="primary" onClick={() => app.modal('Create user', <UserForm onSaved={reload} />)}><Icon name="plus" />Add user</button></Heading>
    <div className="notice">Administrators manage the whole workspace. Editors can update assigned organizations. Viewers can read documentation but cannot reveal secrets. Clients see only assigned organizations and records explicitly marked “Client visible”.</div>
    <Remote state={state}>{rows => <div className="panel"><div className="table-scroll"><table>
      <thead><tr><th>User</th><th>Role</th><th>Organization access</th><th>MFA</th><th>Status</th><th></th></tr></thead>
      <tbody>{rows.map(u => <tr key={u.id}>
        <td><strong>{u.name}</strong><small>{u.email}</small></td><td>{u.role}</td>
        <td>{u.orgs.length ? u.orgs.map(app.title).join(', ') : 'All organizations'}</td>
        <td>{u.mfa ? 'Enabled' : 'Not enabled'}</td><td><Badge value={u.active ? 'Active' : 'Inactive'} /></td>
        <td><button onClick={() => app.modal('Edit user access', <UserForm existing={u} onSaved={reload} />)}>Edit access</button></td></tr>)}</tbody>
    </table></div></div>}</Remote>
  </>;
}

interface AuditRow { time: string; actor: string; action: string; target: string; details: string }
export function Audit() {
  const app = useApp();
  const state = useRemote<AuditRow[]>('/audit', null);
  if (!app.admin) return <Empty title="Administrator access required" />;
  return <>
    <Heading title="Audit log" sub="Server-recorded changes, sign-ins, and secret access. Most recent 1,000 events.">
      <button disabled={!state[0]} onClick={() => download(JSON.stringify(state[0], null, 2), 'trinetra-audit.json')}><Icon name="download" />Export audit</button></Heading>
    <Remote state={state}>{rows => <div className="panel"><div className="table-scroll"><table>
      <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Record</th><th>Details</th></tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}><td>{when(r.time)}</td><td>{r.actor}</td><td>{r.action.replaceAll('_', ' ')}</td>
        <td>{(r.target && app.byId(r.target)?.name) || r.target}</td><td>{r.details}</td></tr>)}</tbody>
    </table></div></div>}</Remote>
  </>;
}

export const listTypes = Object.keys(schema).filter(t => !['racks', 'diagrams'].includes(t)) as Entity[];
