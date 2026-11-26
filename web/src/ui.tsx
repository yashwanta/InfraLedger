import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { names, paths, type Entity } from './model';
import { errorMessage, tone } from './lib';
import { useApp, type ModalSize } from './ctx';

/** Icon paths are static constants from model.ts, never user data. */
export const Icon = ({ name }: { name: string }) =>
  <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" dangerouslySetInnerHTML={{ __html: paths[name] || paths.articles }} />;

export const Badge = ({ value }: { value?: unknown }) => {
  const text = String(value || '—');
  return <span className={`pill ${tone(text)}`}>{text}</span>;
};

export function Empty({ title, description = '', type = '' }: { title: string; description?: string; type?: string }) {
  const app = useApp();
  return <div className="empty">
    <Icon name={type || 'articles'} /><strong>{title}</strong>{description}
    {type && app.writable && schemaType(type) && <div><button className="primary" onClick={() => app.edit(type as Entity)}><Icon name="plus" />Create first record</button></div>}
  </div>;
}
const schemaType = (t: string) => t in names && !['dashboard', 'renewals', 'reports', 'users', 'activity', 'settings', 'trash', 'favorites'].includes(t);

export const Heading = ({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) =>
  <div className="heading"><div><h1>{title}</h1><p className="subtitle">{sub || ''}</p></div><div className="actions">{children}</div></div>;

export const PanelHead = ({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) =>
  <div className="panel-head"><div><h2>{title}</h2>{sub && <p>{sub}</p>}</div>{children}</div>;

export const Stat = ({ label, value, type, note }: { label: string; value: ReactNode; type: string; note: string }) =>
  <div className="stat"><label>{label}</label><span className="stat-icon"><Icon name={type} /></span><strong>{value}</strong><small>{note}</small></div>;

export function AddButton({ type, label = 'Add record' }: { type: Entity; label?: string }) {
  const app = useApp();
  return app.writable ? <button className="primary" onClick={() => app.edit(type)}><Icon name="plus" />{label}</button> : null;
}

export function ViewLink({ page, text = 'View all' }: { page: string; text?: string }) {
  const app = useApp();
  return <button className="text-button" onClick={() => app.navigate(page)}>{text}</button>;
}

/** Button that disables itself while its async action runs and reports failures as a toast. */
export function Act({ onClick, children, ...rest }: { onClick: () => unknown; children: ReactNode } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'onClick'>) {
  const app = useApp();
  const [busy, setBusy] = useState(false);
  return <button type="button" {...rest} disabled={busy || rest.disabled} onClick={async () => {
    setBusy(true);
    try { await onClick(); } catch (e) { app.toast(errorMessage(e)); } finally { setBusy(false); }
  }}>{children}</button>;
}

/** Form submit handling: prevents default, tracks busy state and shows errors inside the form. */
export function useSubmit(handler: (data: Record<string, string>, form: HTMLFormElement) => Promise<unknown> | unknown) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);
  const onSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    setError(''); setBusy(true);
    try { await handler(Object.fromEntries(new FormData(form)) as Record<string, string>, form); }
    catch (err) { if (mounted.current) setError(errorMessage(err)); }
    finally { if (mounted.current) setBusy(false); }
  }, [handler]);
  return { onSubmit, busy, error: error ? <div className="form-error">{error}</div> : null };
}

export function Modal({ title, size, onClose, children }: { title: string; size: ModalSize; onClose: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLElement>(null);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    document.body.style.overflow = 'hidden';
    setTimeout(() => (dialog.current?.querySelector('input,select,textarea,button') as HTMLElement | null)?.focus(), 0);
    return () => { document.body.style.overflow = ''; prior?.focus?.(); };
  }, []);
  const trap = (e: React.KeyboardEvent) => {
    if (e.key !== 'Tab' || !dialog.current) return;
    const els = [...dialog.current.querySelectorAll<HTMLElement>('button,input,textarea,select,a[href],summary')]
      .filter(el => !(el as HTMLButtonElement).disabled && el.getClientRects().length);
    if (!els.length) return;
    if (e.shiftKey && document.activeElement === els[0]) { e.preventDefault(); els.at(-1)!.focus(); }
    else if (!e.shiftKey && document.activeElement === els.at(-1)) { e.preventDefault(); els[0].focus(); }
  };
  return <div id="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
    <section id="dialog" ref={dialog} className={size} role="dialog" aria-modal="true" aria-labelledby="dialog-title" onKeyDown={trap}>
      <div className="dialog-heading"><h2 id="dialog-title">{title}</h2><button className="close" onClick={onClose} aria-label="Close dialog">×</button></div>
      {children}
    </section>
  </div>;
}

export function Confirm({ text, label, danger, onConfirm, notice }: { text: ReactNode; label: string; danger?: boolean; notice?: ReactNode; onConfirm: () => unknown }) {
  const app = useApp();
  return <>
    <p className="subtitle">{text}</p>
    {notice}
    <div className="form-actions"><button onClick={app.close}>Cancel</button><Act className={danger ? 'danger' : 'primary'} onClick={onConfirm}>{label}</Act></div>
  </>;
}

/** Clickable table row / card that opens a record and is keyboard accessible. */
export function recordProps(app: { openDetail(id: string): Promise<void>; toast(m: string): void }, id: string) {
  const open = () => app.openDetail(id).catch(e => app.toast(errorMessage(e)));
  return { tabIndex: 0, onClick: open, onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); open(); } } };
}
