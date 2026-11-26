import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { groups, names, schema, type Entity, type User } from './model';
import { api, days, errorMessage, initials, setCsrf, setTimeZone, type Rec } from './lib';
import { Ctx, useApp, type AppCtx, type Expiration, type ModalSize } from './ctx';
import { Act, Icon, Modal, useSubmit } from './ui';
import { Detail, RecordForm, defaults, recordNoun } from './dialogs';
import { DiagramPage, saveDiagram, type DiagramState } from './diagram';
import { Audit, Dashboard, Expirations, Favorites, ListPage, Racks, Reports, Settings, Trash, Users } from './pages';

type Boot = { state: 'loading' } | { state: 'error'; message: string } | { state: 'auth'; setup: boolean } | { state: 'ready' };

function Brand() {
  return <><img src="/favicon.svg" alt="" /><span>trinetra<small>IT DOCUMENTATION</small></span></>;
}

function AuthScreen({ setup, onSignedIn }: { setup: boolean; onSignedIn: (r: { user: User; csrf: string }) => Promise<void> }) {
  const { onSubmit, busy, error } = useSubmit(async (data, form) => {
    const samples = !!(form.elements.namedItem('samples') as HTMLInputElement | null)?.checked;
    await onSignedIn(await api(setup ? '/setup' : '/login', 'POST', { ...data, samples }));
  });
  return <div className="auth-screen">
    <div className="auth-art"><div className="brand"><Brand /></div>
      <div className="auth-copy"><div className="eyebrow">YOUR KNOWLEDGE. CONNECTED.</div><h1>Clarity for your<br /><span>entire IT world.</span></h1>
        <p>From a single credential to your entire network.<br />One place to document, connect, and understand<br />the systems your team depends on.</p></div>
      <footer>Inventory · Networks · Knowledge · Operations</footer></div>
    <div className="auth-form-wrap"><form className="auth-form" onSubmit={onSubmit}>
      <h2>{setup ? 'Create your workspace' : 'Welcome back'}</h2>
      <p className="subtitle">{setup ? 'Set up your first administrator account.' : 'Sign in to your Trinetra workspace.'}</p>
      {setup && <label className="form-field">Full name<input name="name" required autoComplete="name" maxLength={120} /></label>}
      <label className="form-field">Email<input name="email" type="email" required autoComplete="username" /></label>
      <label className="form-field">Password<input name="password" type="password" required minLength={setup ? 12 : undefined} maxLength={256} autoComplete={setup ? 'new-password' : 'current-password'} /></label>
      {setup ? <><small>Use at least 12 characters.</small>
        <label className="check-label" style={{ marginTop: 18 }}><input name="samples" type="checkbox" defaultChecked />Include fictional example records</label></>
        : <label className="form-field">Authenticator code <small>(if MFA is enabled)</small><input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} pattern="[0-9]{6}" /></label>}
      {error}
      <button className="primary" type="submit" disabled={busy}>{setup ? 'Create workspace' : 'Sign in'}</button>
      <div className="auth-foot">Your workspace is stored on this server. {setup ? 'Keep the database and vault key backed up together.' : 'Sessions expire after eight hours.'}</div>
    </form></div>
  </div>;
}

const hashPage = () => { const p = location.hash.slice(1); return names[p] ? p : 'dashboard'; };

export default function App() {
  const [boot, setBoot] = useState<Boot>({ state: 'loading' });
  const [user, setUser] = useState<User | null>(null);
  const [records, setRecords] = useState<Rec[]>([]);
  const [favorites, setFavorites] = useState<Rec[]>([]);
  const [page, setPage] = useState(hashPage);
  const [scope, setScope] = useState('');
  const [dialog, setDialog] = useState<{ title: string; content: ReactNode; size: ModalSize; key: number } | null>(null);
  const [toastMsg, setToastMsg] = useState({ text: '', visible: false });
  const [diagram, setDiagram] = useState<DiagramState>({ id: '', draft: null, dirty: false });
  const [menuOpen, setMenuOpen] = useState(false);
  const toastTimer = useRef<number>(undefined);
  const dialogKey = useRef(0);

  const toast = useCallback((text: string) => {
    setToastMsg({ text, visible: true });
    clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToastMsg(t => ({ ...t, visible: false })), 4500);
  }, []);
  const modal = useCallback((title: string, content: ReactNode, size: ModalSize = '') => setDialog({ title, content, size, key: ++dialogKey.current }), []);
  const close = useCallback(() => setDialog(null), []);

  const reload = useCallback(async () => {
    const [r, f] = await Promise.all([api<Rec[]>('/records'), api<Rec[]>('/favorites')]);
    setRecords(r); setFavorites(f);
  }, []);

  const signedIn = useCallback(async (result: { user: User; csrf: string }) => {
    setCsrf(result.csrf); setUser(result.user);
    await reload();
    setBoot({ state: 'ready' });
  }, [reload]);

  useEffect(() => {
    (async () => {
      try {
        const status = await api('/status');
        setTimeZone(status.timeZone);
        if (status.setupRequired) return setBoot({ state: 'auth', setup: true });
        const me = await api('/me');
        if (!me) return setBoot({ state: 'auth', setup: false });
        await signedIn(me);
      } catch (e) { setBoot({ state: 'error', message: errorMessage(e) }); }
    })();
  }, [signedIn]);

  // Derived lookups.
  const byIdMap = useMemo(() => new Map(records.map(r => [r.id, r])), [records]);
  const byId = useCallback((id?: string) => id ? byIdMap.get(id) : undefined, [byIdMap]);
  const inScope = useCallback((r: Rec) => !scope || r.orgId === scope || r.id === scope, [scope]);
  const expirations = useCallback((): Expiration[] => records.filter(inScope)
    .flatMap(r => [...(r.expires ? [{ r, date: r.expires, kind: 'Expiration' as const }] : []), ...(r.reviewDate ? [{ r, date: r.reviewDate, kind: 'Review' as const }] : [])])
    .filter(v => days(v.date) <= 90).sort((a, b) => a.date.localeCompare(b.date)), [records, inScope]);

  const doSaveDiagram = useCallback(async () => {
    const saved = await saveDiagram(diagram);
    await reload();
    setDiagram({ id: saved.id, draft: structuredClone(saved), dirty: false });
    setDialog(null);
    toast('Diagram saved');
  }, [diagram, reload, toast]);

  const unsavedGuard = useCallback((proceed: () => void, message = 'Save your diagram before leaving, or discard the changes.') => {
    if (!diagram.dirty) return proceed();
    modal('Unsaved diagram changes', <><p className="subtitle">{message}</p>
      <div className="form-actions"><button onClick={() => setDialog(null)}>Keep editing</button>
        <button onClick={() => { setDiagram(d => ({ ...d, dirty: false, draft: null })); setDialog(null); proceed(); }}>Discard changes</button>
        <Act className="primary" onClick={async () => { await doSaveDiagram(); proceed(); }}>Save diagram</Act></div></>, 'small');
  }, [diagram.dirty, modal, doSaveDiagram]);

  const navigate = useCallback((p: string) => {
    const go = () => { setPage(p); setDialog(null); setMenuOpen(false); if (location.hash.slice(1) !== p) location.hash = p; };
    if (p === 'diagrams') go(); else unsavedGuard(go);
  }, [unsavedGuard]);

  useEffect(() => {
    const onHash = () => { const p = location.hash.slice(1); if (names[p] && p !== page) navigate(p); };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, [page, navigate]);

  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => { if (diagram.dirty) { e.preventDefault(); e.returnValue = ''; } };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [diagram.dirty]);

  useEffect(() => { document.body.classList.toggle('menu-open', menuOpen); }, [menuOpen]);

  const logout = useCallback(() => unsavedGuard(async () => {
    try { await api('/logout', 'POST', {}); } catch (e) { toast(errorMessage(e)); return; }
    setCsrf(''); setUser(null); setRecords([]); setFavorites([]); setDialog(null);
    setBoot({ state: 'auth', setup: false });
  }, 'Save your diagram before signing out.'), [unsavedGuard, toast]);

  const ctx = useMemo<AppCtx | null>(() => {
    if (!user) return null;
    const writable = user.role === 'admin' || user.role === 'editor';
    const self: AppCtx = {
      user, records, favorites, scope, writable, admin: user.role === 'admin',
      byId, inScope, expirations, reload, toast, modal, close, navigate,
      setUser,
      title: id => byId(id)?.name || '—',
      ofType: t => records.filter(r => r.type === t),
      openDetail: async id => { const r = await api<Rec>('/records/' + id); modal(r.name, <Detail initial={r} />, r.type === 'articles' ? 'wide' : ''); },
      openDiagram: id => {
        const go = () => { setDiagram({ id, draft: structuredClone(byId(id)) as any, dirty: false }); navigate('diagrams'); };
        if (diagram.dirty && id !== diagram.id) unsavedGuard(go); else { setDialog(null); go(); }
      },
      edit: (type: Entity, id?: string, preset: Partial<Rec> = {}) => {
        const existing = id ? byId(id) : undefined;
        if (id && !existing) { toast('Record unavailable'); return; }
        const record = existing ? structuredClone(existing) : { orgId: scope || records.find(r => r.type === 'organizations')?.id, ...defaults(type), ...preset };
        const onSaved = (r: Rec) => { if (type === 'diagrams') { setDiagram({ id: r.id, draft: structuredClone(r) as any, dirty: false }); navigate('diagrams'); } };
        modal(`${id ? 'Edit' : 'New'} ${recordNoun(type)}`, <RecordForm type={type} record={record} onSaved={onSaved} />, type === 'articles' ? 'wide' : '');
      },
    };
    return self;
  }, [user, records, favorites, scope, byId, inScope, expirations, reload, toast, modal, close, navigate, diagram, unsavedGuard]);

  // Keyboard shortcuts: Ctrl/⌘+K focuses search, Escape closes overlays.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); document.getElementById('global-search')?.focus(); }
      if (e.key === 'Escape') { setDialog(null); setMenuOpen(false); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const toastEl = <div id="toast" role="status" className={toastMsg.visible ? 'visible' : ''}>{toastMsg.text}</div>;

  if (boot.state === 'loading') return <div className="loading">Loading your workspace…</div>;
  if (boot.state === 'error') return <div className="empty"><strong>Unable to open the workspace</strong>{boot.message}<p>Check that the server is running, then refresh this page.</p></div>;
  if (boot.state === 'auth' || !ctx) return <>{boot.state === 'auth' && <AuthScreen setup={boot.setup} onSignedIn={signedIn} />}{toastEl}</>;

  const changeScope = (value: string) => {
    if (diagram.dirty) { toast('Save the diagram before changing organization scope'); return; }
    setScope(value);
    setDiagram({ id: '', draft: null, dirty: false });
  };
  const onPasswordChanged = (r: { user: User; csrf: string }) => { setCsrf(r.csrf); setUser(r.user); };

  return <Ctx.Provider value={ctx}>
    <Sidebar page={page} onLogout={logout} />
    <div className="app">
      <header className="topbar">
        <button className="icon-button mobile-menu" aria-label="Toggle navigation" onClick={() => setMenuOpen(m => !m)}>☰</button>
        <div className="breadcrumbs">Workspace<span>/</span><b>{names[page]}</b></div>
        <div className="top-actions">
          <GlobalSearch />
          <select className="org-scope" aria-label="Organization scope" value={scope} onChange={e => changeScope(e.target.value)}>
            <option value="">All organizations</option>
            {ctx.ofType('organizations').map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
          {user!.role === 'client' ? <span className="client-indicator">Client</span> : <span className="avatar">{initials(user!.name)}</span>}
        </div>
      </header>
      <main id="main"><PageView page={page} diagram={diagram} setDiagram={setDiagram} saveDiagram={doSaveDiagram} onPasswordChanged={onPasswordChanged} /></main>
      <footer className="footer"><span>Trinetra IT · Self-hosted workspace</span><span>Knowledge that keeps your team moving.</span></footer>
    </div>
    {dialog && <Modal key={dialog.key} title={dialog.title} size={dialog.size} onClose={close}>{dialog.content}</Modal>}
    {toastEl}
  </Ctx.Provider>;
}

function PageView({ page, diagram, setDiagram, saveDiagram, onPasswordChanged }: {
  page: string; diagram: DiagramState; setDiagram: (s: DiagramState) => void; saveDiagram: () => Promise<void>; onPasswordChanged: (r: { user: User; csrf: string }) => void;
}) {
  if (page in schema && page !== 'racks' && page !== 'diagrams') return <ListPage key={page} type={page as Entity} />;
  switch (page) {
    case 'dashboard': return <Dashboard />;
    case 'renewals': return <Expirations />;
    case 'racks': return <Racks />;
    case 'diagrams': return <DiagramPage state={diagram} setState={setDiagram} save={saveDiagram} />;
    case 'reports': return <Reports />;
    case 'settings': return <Settings onPasswordChanged={onPasswordChanged} />;
    case 'favorites': return <Favorites />;
    case 'trash': return <Trash />;
    case 'users': return <Users />;
    case 'activity': return <Audit />;
    default: return <div className="empty"><strong>Page unavailable</strong></div>;
  }
}

const clientHidden = ['passwords', 'purchases', 'vendors', 'templates', 'reports'];

function Sidebar({ page, onLogout }: { page: string; onLogout: () => void }) {
  const app = useApp();
  const u = app.user;
  const due = app.expirations().length;
  const allowed = (p: string) => !(['users', 'activity'].includes(p) && !app.admin) && !(p === 'trash' && !app.writable) && !(u.role === 'client' && clientHidden.includes(p));
  return <aside className="sidebar">
    <a href="#dashboard" className="brand" onClick={e => { e.preventDefault(); app.navigate('dashboard'); }}><Brand /></a>
    <div className="scope-card"><span className="scope-icon"><Icon name="organizations" /></span>
      <div>{u.role === 'client' ? 'Client workspace' : 'IT Operations'}<small>{u.role === 'client' ? 'Your shared documentation' : 'Connected documentation'}</small></div></div>
    <div className="nav-scroll">{groups.map(([label, pages]) => {
      const items = pages.filter(allowed);
      if (!items.length) return null;
      return <div key={label}><div className="nav-group">{label}</div>
        {items.map(p => <a key={p} className={`nav-link ${page === p ? 'active' : ''}`} href={'#' + p} onClick={e => { e.preventDefault(); app.navigate(p); }}>
          <Icon name={p} />{names[p]}{p === 'renewals' && due > 0 && <span className="count">{due}</span>}</a>)}</div>;
    })}</div>
    <div className="sidebar-bottom"><div className="profile"><span className="avatar">{initials(u.name)}</span>
      <span>{u.name}<small>{u.role === 'client' ? 'Client access' : u.role + ' access'}</small></span>
      <button className="icon-button" aria-label="Sign out" onClick={onLogout}><Icon name="logout" /></button></div></div>
  </aside>;
}

function GlobalSearch() {
  const app = useApp();
  const [term, setTerm] = useState('');
  const [results, setResults] = useState<Rec[] | null>(null);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const q = term.trim();
    if (!q) { setResults(null); return; }
    let live = true;
    const timer = setTimeout(() => api<Rec[]>('/records?q=' + encodeURIComponent(q))
      .then(r => { if (live) setResults(r.filter(app.inScope).slice(0, 15)); })
      .catch(e => app.toast(errorMessage(e))), 150);
    return () => { live = false; clearTimeout(timer); };
  }, [term, app.inScope]);
  useEffect(() => {
    const outside = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setResults(null); };
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setResults(null); };
    document.addEventListener('mousedown', outside);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', outside); document.removeEventListener('keydown', esc); };
  }, []);
  return <div ref={box} style={{ display: 'contents' }}>
    <div className="searchbox"><Icon name="search" />
      <input id="global-search" aria-label="Search workspace" placeholder="Search your workspace…" autoComplete="off" value={term}
        onChange={e => setTerm(e.target.value)} /><kbd>Ctrl K</kbd></div>
    {results && <div id="search-results">
      {results.map(r => <button key={r.id} onClick={() => { setResults(null); app.openDetail(r.id).catch(e => app.toast(errorMessage(e))); }}>
        {r.name}<small>{names[r.type]} · {app.title(r.orgId)}</small></button>)}
      {!results.length && <div className="empty">No matching records.</div>}
    </div>}
  </div>;
}
