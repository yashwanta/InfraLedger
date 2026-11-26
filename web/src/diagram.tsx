import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { Diagram, DiagramNode } from './model';
import { api, download, errorMessage } from './lib';
import { useApp } from './ctx';
import { Act, AddButton, Empty, Heading, Icon } from './ui';
import { subtitles } from './model';

const glyph = (kind: string) => kind === 'cloud' ? '☁' : kind === 'server' ? '▤' : kind === 'firewall' ? '▦' : '◇';
const curve = (a: DiagramNode, b: DiagramNode) => `M${a.x + 160} ${a.y + 39} C${a.x + 210} ${a.y + 39},${b.x - 50} ${b.y + 39},${b.x} ${b.y + 39}`;
const font = 'Segoe UI,sans-serif';

interface SvgProps {
  d: Pick<Diagram, 'name' | 'nodes' | 'edges'>;
  selected?: string;
  svgRef?: React.Ref<SVGSVGElement>;
  onNodeDown?: (e: React.PointerEvent, node: DiagramNode) => void;
  onNodeKey?: (node: DiagramNode) => void;
}

export function DiagramSvg({ d, selected, svgRef, onNodeDown, onNodeKey }: SvgProps) {
  const nodes = d.nodes || [], edges = d.edges || [];
  const editable = !!onNodeDown;
  const maxX = Math.max(1100, ...nodes.map(n => n.x + 210)), maxY = Math.max(560, ...nodes.map(n => n.y + 130));
  return <svg ref={svgRef} className={editable ? 'diagram-canvas' : undefined} xmlns="http://www.w3.org/2000/svg" viewBox={`0 0 ${maxX} ${maxY}`} role="img" aria-label={d.name}>
    <defs><marker id="edge-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#8aa6b3" /></marker></defs>
    {edges.map((e, i) => {
      const a = nodes.find(n => n.id === e.from), b = nodes.find(n => n.id === e.to);
      if (!a || !b) return null;
      return <g key={i} className="edge">
        <path d={curve(a, b)} fill="none" stroke="#94adb8" strokeWidth="1.6" markerEnd="url(#edge-arrow)" />
        <text x={(a.x + 160 + b.x) / 2} y={(a.y + b.y) / 2 + 22} textAnchor="middle" fill="#8199a9" fontFamily={font} fontSize="10">{e.label}</text>
      </g>;
    })}
    {nodes.map(n => <g key={n.id} className={`node ${selected === n.id ? 'selected' : ''}`} transform={`translate(${n.x},${n.y})`}
      {...(editable ? {
        tabIndex: 0, role: 'button', 'aria-label': `Select ${n.label}`,
        onPointerDown: (e: React.PointerEvent) => onNodeDown!(e, n),
        onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter') onNodeKey?.(n); },
      } : {})}>
      <rect width="160" height="78" rx="8" fill="white" stroke="#bdcfd8" />
      <rect x="12" y="15" width="30" height="30" rx="7" fill="#e4f1eb" stroke="none" />
      <text x="27" y="36" textAnchor="middle" fill="#63937e" fontSize="17">{glyph(n.kind)}</text>
      <text x="52" y="30" fontFamily={font} fontSize="12" fill="#426174">{n.label.slice(0, 17)}</text>
      <text className="node-kind" x="52" y="48" fontFamily={font} fontSize="9" fill="#829dab">{n.kind || 'device'}</text>
      <text x="14" y="66" fontFamily={font} fontSize="9" fill="#829dab">{n.assetId ? 'Linked inventory asset' : 'Diagram component'}</text>
    </g>)}
  </svg>;
}

/** Diagram editor state lives in App so navigation can guard unsaved changes. */
export interface DiagramState { id: string; draft: Diagram | null; dirty: boolean }

export function DiagramPage({ state, setState, save }: { state: DiagramState; setState: (s: DiagramState) => void; save: () => Promise<void> }) {
  const app = useApp();
  const diagrams = app.ofType('diagrams').filter(app.inScope) as unknown as Diagram[];
  const [selected, setSelected] = useState('');
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ id: string; dx: number; dy: number } | null>(null);
  const stateRef = useRef(state);
  stateRef.current = state;

  // Open the first diagram in scope when nothing (or a diagram from another scope) is loaded.
  useEffect(() => {
    if (!state.draft || !diagrams.some(d => d.id === state.id)) {
      const first = diagrams[0];
      setState({ id: first?.id || '', draft: first ? structuredClone(first) : null, dirty: false });
      setSelected('');
    }
  }, [state.id, state.draft, diagrams.map(d => d.id).join()]);

  useEffect(() => {
    const point = (e: PointerEvent) => new DOMPoint(e.clientX, e.clientY).matrixTransform(svg.current!.getScreenCTM()!.inverse());
    const move = (e: PointerEvent) => {
      const s = stateRef.current;
      if (!drag.current || !s.draft || !svg.current) return;
      const p = point(e), { id, dx, dy } = drag.current;
      const nodes = s.draft.nodes.map(n => n.id === id
        ? { ...n, x: Math.round(Math.max(0, Math.min(1800, p.x - dx))), y: Math.round(Math.max(0, Math.min(1200, p.y - dy))) } : n);
      setState({ ...s, draft: { ...s.draft, nodes }, dirty: true });
    };
    const up = () => { drag.current = null; };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
  }, [setState]);

  const draft = state.draft;
  if (!draft) return <><Heading title="Infrastructure diagrams" sub={subtitles.diagrams}><AddButton type="diagrams" label="New diagram" /></Heading>
    <Empty title="Draw your first diagram" description="Add connected devices and label network flows." type="diagrams" /></>;

  const update = (next: Partial<Diagram>) => setState({ ...state, draft: { ...draft, ...next }, dirty: true });
  const node = draft.nodes.find(n => n.id === selected);

  const onNodeDown = (e: React.PointerEvent, n: DiagramNode) => {
    setSelected(n.id);
    if (!app.writable || !svg.current) return;
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(svg.current.getScreenCTM()!.inverse());
    drag.current = { id: n.id, dx: p.x - n.x, dy: p.y - n.y };
    e.preventDefault();
  };

  const switchTo = (id: string) => {
    if (state.dirty) {
      app.modal('Unsaved diagram changes', <><p className="subtitle">Save your changes or discard them before opening another diagram.</p>
        <div className="form-actions"><button onClick={app.close}>Keep editing</button>
          <button onClick={() => { app.close(); setState({ id, draft: structuredClone(app.byId(id) as unknown as Diagram), dirty: false }); setSelected(''); }}>Discard changes</button>
          <Act className="primary" onClick={save}>Save diagram</Act></div></>, 'small');
      return;
    }
    setState({ id, draft: structuredClone(app.byId(id) as unknown as Diagram), dirty: false });
    setSelected('');
  };

  const exportSvg = () => {
    if (!svg.current) return;
    const clone = svg.current.cloneNode(true) as SVGSVGElement;
    clone.removeAttribute('class');
    clone.querySelectorAll('g.node').forEach(g => { g.removeAttribute('tabindex'); g.removeAttribute('role'); g.removeAttribute('aria-label'); g.setAttribute('class', 'node'); });
    download(new XMLSerializer().serializeToString(clone), draft.name.replace(/[^a-z0-9-]/gi, '-') + '.svg', 'image/svg+xml');
  };

  const submitNode = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    const props = { label: data.label, kind: data.kind, assetId: data.assetId || undefined };
    if (node) update({ nodes: draft.nodes.map(n => n.id === node.id ? { ...n, ...props } : n) });
    else {
      const id = crypto.randomUUID(), count = draft.nodes.length;
      update({ nodes: [...draft.nodes, { ...props, id, x: 80 + (count % 4) * 250, y: 90 + Math.floor(count / 4) * 140 }] });
      setSelected(id);
    }
  };

  const submitEdge = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const data = Object.fromEntries(new FormData(form)) as { from: string; to: string; label: string };
    try {
      if (data.from === data.to) throw new Error('Choose two different components');
      if (draft.edges.some(v => v.from === data.from && v.to === data.to && v.label === data.label)) throw new Error('This connection already exists');
      update({ edges: [...draft.edges, data] });
      form.reset();
    } catch (err) { app.toast(errorMessage(err)); }
  };

  const label = (id: string) => draft.nodes.find(n => n.id === id)?.label;

  return <>
    <Heading title="Infrastructure diagrams" sub={subtitles.diagrams}><AddButton type="diagrams" label="New diagram" /></Heading>
    <div className="diagram-toolbar">
      <select aria-label="Select diagram" value={state.id} onChange={e => switchTo(e.target.value)}>{diagrams.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</select>
      {app.writable && <Act className="primary" onClick={save}><Icon name="save" />Save diagram</Act>}
      <button onClick={exportSvg}><Icon name="download" />Export SVG</button>
      <button onClick={() => app.openDetail(state.id)}>Details</button>
      <span className="muted" style={{ fontSize: 12 }}>{state.dirty ? 'Unsaved changes' : 'All changes saved'}</span>
    </div>
    <div className="diagram-layout">
      <div className="diagram-wrap"><DiagramSvg d={draft} selected={selected} svgRef={svg} onNodeDown={onNodeDown} onNodeKey={n => setSelected(n.id)} /></div>
      <div><div className="panel diagram-side">
        <h3>{node ? 'Selected component' : 'Diagram tools'}</h3>
        <small>{app.writable ? 'Drag components to arrange the diagram. Select one to edit its label or link an inventory asset.' : 'View the documented topology and export a diagram.'}</small>
        {app.writable && <>
          <form key={selected || 'new'} onSubmit={submitNode}>
            <label className="form-field">Component label<input name="label" required maxLength={100} defaultValue={node?.label || ''} /></label>
            <label className="form-field">Type<select name="kind" defaultValue={node?.kind || 'device'}>{['device', 'cloud', 'firewall', 'switch', 'server', 'workstation', 'service'].map(v => <option key={v}>{v}</option>)}</select></label>
            <label className="form-field">Inventory asset<select name="assetId" defaultValue={node?.assetId || ''}><option value="">Standalone component</option>
              {app.ofType('assets').filter(a => a.orgId === draft.orgId).map(a => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
            <button type="submit" className="primary">{node ? 'Update component' : 'Add component'}</button>
          </form>
          {node && <>
            <button className="danger" onClick={() => { update({ nodes: draft.nodes.filter(n => n.id !== node.id), edges: draft.edges.filter(e => e.from !== node.id && e.to !== node.id) }); setSelected(''); }}>Remove component</button>
            <button onClick={() => setSelected('')}>Add a different component</button>
          </>}
          <div className="detail-section"><h3>Add a connection</h3>
            <form onSubmit={submitEdge}>
              <label className="form-field">From<select name="from" required><option value="">Choose component</option>{draft.nodes.map(n => <option key={n.id} value={n.id}>{n.label}</option>)}</select></label>
              <label className="form-field">To<select name="to" required><option value="">Choose component</option>{draft.nodes.map(n => <option key={n.id} value={n.id}>{n.label}</option>)}</select></label>
              <label className="form-field">Protocol / flow label<input name="label" maxLength={100} placeholder="HTTPS · TCP 443" /></label>
              <button type="submit">Connect components</button>
            </form></div>
          <div className="detail-section"><h3>Connections</h3>
            {draft.edges.map((e, i) => <div key={i} style={{ display: 'flex', gap: 7, fontSize: 11, marginBottom: 8 }}>
              <span style={{ flex: 1 }}>{label(e.from)} / {label(e.to)}<small>{e.label}</small></span>
              <button className="icon-button danger" style={{ width: 'auto' }} aria-label="Remove connection" onClick={() => update({ edges: draft.edges.filter((_, n) => n !== i) })}>×</button>
            </div>)}
            {!draft.edges.length && <small>No connections yet.</small>}
          </div>
        </>}
      </div></div>
    </div>
  </>;
}

export async function saveDiagram(state: DiagramState): Promise<Diagram> {
  if (!state.draft) throw new Error('No diagram open');
  return api<Diagram>('/records/' + state.id, 'PUT', state.draft);
}
