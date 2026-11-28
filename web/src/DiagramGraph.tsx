import {useEffect,useRef,useState} from 'react';
import {type DiagramEdge,type DiagramNode} from './model';

// Shared SVG renderer for saved diagrams, the dashboard preview and the live
// dependency map. Edges are routed from the side that faces the other
// component: top-down layouts get orthogonal "org chart" connectors, children
// stacked in an indented list get a rail, and left-to-right layouts (the
// dependency map, flow="right") get horizontal curves. The view fits the
// drawing to the available space; wheel zooms and dragging the background pans.

export const NODE_W=176,NODE_H=60;

const ICONS:Record<string,string>={
 cloud:'M7 18h10a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.1 9.2 4.5 4.5 0 0 0 7 18z',
 firewall:'M3 5h18v14H3zM3 9.7h18M3 14.3h18M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19',
 switch:'M3 7h18v10H3zM7 11h.01M10 11h.01M13 11h.01M16 11h.01M7 14h10',
 server:'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01M12 7h4M12 17h4',
 workstation:'M3 4h18v12H3zM8 20h8M12 16v4',
 service:'M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12 4 7.5',
 port:'M6 4h12v10l-3 3H9l-3-3zM10 17v3M14 17v3',
 printer:'M6 9V3h12v6M6 18H4v-7h16v7h-2M6 14h12v7H6z',
 camera:'M3 7h4l2-3h6l2 3h4v12H3zM9 13a3 3 0 1 0 6 0 3 3 0 1 0-6 0',
 phone:'M8 2h8v20H8zM11 18h2',
 media:'M3 5h18v12H3zM8 21h8M10 8.5v5l4-2.5z',
 iot:'M5 10a10 10 0 0 1 14 0M8 13.5a5.5 5.5 0 0 1 8 0M12 17h.01',
 device:'M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
};
const KINDS:Record<string,{label:string;tone:string}>={
 cloud:{label:'Network',tone:'net'},firewall:{label:'Gateway / firewall',tone:'gw'},switch:{label:'Switch',tone:'sw'},
 server:{label:'Server',tone:'srv'},workstation:{label:'Workstation',tone:'ws'},service:{label:'Service',tone:'svc'},
 port:{label:'Port',tone:'sw'},printer:{label:'Printer',tone:'svc'},camera:{label:'Camera',tone:'iot'},
 phone:{label:'Phone / tablet',tone:'ws'},media:{label:'TV / media',tone:'iot'},iot:{label:'IoT device',tone:'iot'},device:{label:'Device',tone:'dev'},
};
const PLURALS:Record<string,string>={applications:'Application',services:'Service',networks:'Network',ports:'Port',assets:'Device'};

/** Maps a node kind (a diagram kind or an asset category) to an icon, tone and readable label. */
export function kindInfo(kind:string){
 const k=(kind||'device').toLowerCase();
 const icon=ICONS[k]?k:/firewall|router|gateway/.test(k)?'firewall':/switch|access point|network device/.test(k)?'switch':/server|virtual|container|storage|ups/.test(k)?'server':/laptop|desktop|workstation|computer/.test(k)?'workstation':/applications|services/.test(k)?'service':k==='networks'?'cloud':k==='ports'?'port':/printer/.test(k)?'printer':/camera/.test(k)?'camera':/phone|tablet/.test(k)?'phone':/tv|media/.test(k)?'media':/iot/.test(k)?'iot':'device';
 const label=KINDS[k]?.label||PLURALS[k]||(kind?kind.charAt(0).toUpperCase()+kind.slice(1):'Device');
 return {icon,label,tone:KINDS[icon].tone};
}

const clip=(s:string,n:number)=>s.length>n?s.slice(0,n-1)+'…':s;

interface Route {d:string;lx:number;ly:number;anchor:'start'|'middle'|'end'}

/** Chooses connection sides from the relative position of the two components. */
export function route(a:DiagramNode,b:DiagramNode,flow:'auto'|'right'='auto',hint?:'list'):Route{
 const W=NODE_W,H=NODE_H,acx=a.x+W/2,bcx=b.x+W/2;
 // Device listed in columns under the parent: a bus under the parent feeds a rail left of each column.
 if(hint==='list'&&b.y>=a.y+H+8&&b.x>=a.x+28){
  const sx=a.x+20,rx=b.x-20,my=b.y+H/2,by=a.y+H+14,x0=rx<=sx+1?sx:rx;
  const head=x0===sx?`M${sx} ${a.y+H}`:`M${sx} ${a.y+H}V${by}H${rx}`;
  return {d:`${head}V${my-6}Q${x0} ${my} ${x0+6} ${my}H${b.x}`,lx:b.x+W+6,ly:my+4,anchor:'start'};
 }
 if(flow==='auto'){
  // Indented list under the parent: rail down from the parent's left side.
  if(b.y>=a.y+H+8&&b.x>a.x+8&&b.x<a.x+W/2){
   const rx=a.x+20,my=b.y+H/2;
   return {d:`M${rx} ${a.y+H}V${my-6}Q${rx} ${my} ${rx+6} ${my}H${b.x}`,lx:b.x+W+6,ly:my+4,anchor:'start'};
  }
  const down=b.y>=a.y+H+16,up=a.y>=b.y+H+16;
  if(down||up){
   const y1=down?a.y+H:a.y,y2=down?b.y:b.y+H,my=Math.round((y1+y2)/2),sy=down?1:-1;
   const lx=bcx+6,ly=down?y2-7:y2+14;
   if(Math.abs(acx-bcx)<1)return {d:`M${acx} ${y1}V${y2}`,lx,ly,anchor:'start'};
   const sx=Math.sign(bcx-acx),r=Math.min(8,Math.abs(bcx-acx)/2,Math.abs(my-y1));
   return {d:`M${acx} ${y1}V${my-sy*r}Q${acx} ${my} ${acx+sx*r} ${my}H${bcx-sx*r}Q${bcx} ${my} ${bcx} ${my+sy*r}V${y2}`,lx,ly,anchor:'start'};
  }
 }
 const ay=a.y+H/2,by=b.y+H/2;
 if(b.x>=a.x+W+12||flow==='right'&&b.x>a.x){const x1=a.x+W,x2=b.x,c=Math.max(30,Math.abs(x2-x1)/2);return {d:`M${x1} ${ay}C${x1+c} ${ay} ${x2-c} ${by} ${x2} ${by}`,lx:(x1+x2)/2,ly:(ay+by)/2-6,anchor:'middle'}}
 if(a.x>=b.x+W+12||flow==='right'&&b.x<a.x){const x1=a.x,x2=b.x+W,c=Math.max(30,Math.abs(x2-x1)/2);return {d:`M${x1} ${ay}C${x1-c} ${ay} ${x2+c} ${by} ${x2} ${by}`,lx:(x1+x2)/2,ly:(ay+by)/2-6,anchor:'middle'}}
 // Same column, overlapping: loop out to the right.
 const x=Math.max(a.x,b.x)+W;
 return {d:`M${a.x+W} ${ay}C${x+50} ${ay} ${x+50} ${by} ${b.x+W} ${by}`,lx:x+30,ly:(ay+by)/2,anchor:'start'};
}

interface GraphProps {compact?:boolean;nodes:DiagramNode[];edges:DiagramEdge[];selected?:string;onSelect?:(id:string)=>void;onMove?:(id:string,x:number,y:number)=>void;onOpen?:(id:string)=>void;labels?:boolean;flow?:'auto'|'right'}
interface View {x:number;y:number;w:number;h:number}

const MAX_FIT=1,MIN_ZOOM=.15,MAX_ZOOM=3;

/** Bounding box of the drawing with room for connection labels. */
function bounds(nodes:DiagramNode[],labels:boolean):View{
 if(!nodes.length)return {x:0,y:0,w:1200,h:560};
 const xs=nodes.map(n=>n.x),ys=nodes.map(n=>n.y),pad=32,extra=labels?80:0;
 const x=Math.min(...xs)-pad,y=Math.min(...ys)-pad;
 return {x,y,w:Math.max(...xs)+NODE_W+pad+extra-x,h:Math.max(...ys)+NODE_H+pad-y};
}

/** The largest view (never above 100%) that shows the whole box in a viewport of the given size. */
function fitView(box:View,size:{w:number;h:number}):View{
 if(!size.w||!size.h)return box;
 const s=Math.min(size.w/box.w,size.h/box.h,MAX_FIT),w=size.w/s,h=size.h/s;
 return {x:box.x+(box.w-w)/2,y:box.y+(box.h-h)/2,w,h};
}

export function Graph({nodes,edges,selected,onSelect,onMove,onOpen,labels=true,compact=false,flow='auto'}:GraphProps){
 const svg=useRef<SVGSVGElement>(null),drag=useRef<{id:string;dx:number;dy:number}|undefined>(undefined),pan=useRef<{cx:number;cy:number;view:View}|undefined>(undefined);
 const [size,setSize]=useState({w:0,h:0}),[view,setView]=useState<View|null>(null);
 const interactive=Boolean(onSelect||onMove);
 useEffect(()=>{const el=svg.current;if(!el)return;const ro=new ResizeObserver(([e])=>setSize({w:e.contentRect.width,h:e.contentRect.height}));ro.observe(el);return()=>ro.disconnect()},[]);
 // Another diagram, an added or removed component, or a resized canvas refits the view.
 const signature=nodes.map(n=>n.id).join();
 useEffect(()=>setView(null),[signature,size.w,size.h]);
 const box=bounds(nodes,labels&&edges.some(e=>e.label)),fit=fitView(box,size),current=view||fit;
 const currentRef=useRef(current);currentRef.current=current;
 const zoom=(factor:number,cx?:number,cy?:number)=>{
  const v=currentRef.current;if(!size.w)return;
  const scale=Math.min(MAX_ZOOM,Math.max(MIN_ZOOM,size.w/v.w*factor)),w=size.w/scale,h=size.h/scale;
  const px=cx??v.x+v.w/2,py=cy??v.y+v.h/2;
  setView({x:px-(px-v.x)*w/v.w,y:py-(py-v.y)*h/v.h,w,h});
 };
 const zoomRef=useRef(zoom);zoomRef.current=zoom;
 useEffect(()=>{const el=svg.current;if(!el||!interactive)return;
  const wheel=(e:WheelEvent)=>{e.preventDefault();const p=new DOMPoint(e.clientX,e.clientY).matrixTransform(el.getScreenCTM()!.inverse());zoomRef.current(Math.exp(-e.deltaY*.0015),p.x,p.y)};
  el.addEventListener('wheel',wheel,{passive:false});return()=>el.removeEventListener('wheel',wheel)},[interactive]);
 const point=(e:React.PointerEvent)=>new DOMPoint(e.clientX,e.clientY).matrixTransform(svg.current!.getScreenCTM()!.inverse());
 const byId=new Map(nodes.map(n=>[n.id,n]));
 const end=()=>{drag.current=undefined;pan.current=undefined};
 const percent=size.w?Math.round(size.w/current.w*100):100;
 return <div className={'graph-viewport'+(compact?' compact':'')}>
  <svg ref={svg} className={'diagram-canvas'+(interactive?' pannable':'')} xmlns="http://www.w3.org/2000/svg" viewBox={`${current.x} ${current.y} ${current.w} ${current.h}`} data-fit={`${box.x} ${box.y} ${box.w} ${box.h}`} aria-label="Infrastructure diagram" role="img"
   onPointerDown={e=>{if(drag.current||!interactive||e.button!==0)return;pan.current={cx:e.clientX,cy:e.clientY,view:current};svg.current?.setPointerCapture(e.pointerId)}}
   onPointerMove={e=>{
    if(drag.current&&onMove){const p=point(e);onMove(drag.current.id,Math.round(Math.max(0,p.x-drag.current.dx)),Math.round(Math.max(0,p.y-drag.current.dy)));return}
    const p=pan.current;if(p&&size.w){const k=p.view.w/size.w;setView({...p.view,x:p.view.x-(e.clientX-p.cx)*k,y:p.view.y-(e.clientY-p.cy)*k})}
   }} onPointerUp={end} onPointerCancel={end}>
   <defs><marker id="edge-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path className="edge-arrow" d="M0 0 10 5 0 10z" fill="#9a9ea9"/></marker></defs>
   <g className="edges">{edges.map((edge,i)=>{const a=byId.get(edge.from),b=byId.get(edge.to);if(!a||!b)return null;const r=route(a,b,flow,edge.route);const active=Boolean(selected&&(edge.from===selected||edge.to===selected));
    return <g key={i} className={'edge'+(active?' active':'')}><path d={r.d} fill="none" stroke={active?'#c3182f':'#b4b8c2'} strokeWidth={active?2.2:1.5} strokeLinejoin="round" markerEnd="url(#edge-arrow)"/>{labels&&edge.label&&<text x={r.lx} y={r.ly} textAnchor={r.anchor} fill="#6b707c" fontFamily="Segoe UI,sans-serif" fontSize="10">{clip(edge.label,28)}</text>}</g>})}</g>
   {nodes.map(n=>{const info=kindInfo(n.kind);return <g className={'node'+(n.id===selected?' selected':'')} key={n.id} transform={`translate(${n.x},${n.y})`} role="button" tabIndex={0} aria-label={'Select '+n.label}
    onPointerDown={e=>{onSelect?.(n.id);if(onMove){const p=point(e);drag.current={id:n.id,dx:p.x-n.x,dy:p.y-n.y};setView(current);svg.current?.setPointerCapture(e.pointerId);e.preventDefault()}}}
    onDoubleClick={()=>onOpen?.(n.assetId||n.id)} onKeyDown={e=>{if(e.key==='Enter')onSelect?.(n.id)}}>
    <rect className="node-card" width={NODE_W} height={NODE_H} rx="10" fill="#fff" stroke="#d7d8de"/>
    <rect className={'node-tile tone-'+info.tone} x="12" y="14" width="32" height="32" rx="8" fill="#f1f2f4"/>
    <path className={'node-icon tone-'+info.tone} transform="translate(17 19) scale(.92)" d={ICONS[info.icon]} fill="none" stroke="#5b6170" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
    <text className="node-label" x="54" y="27" fontFamily="Segoe UI,sans-serif" fontSize="12.5" fontWeight="600" fill="#2e323c">{clip(n.label,17)}</text>
    <text className="node-sub" x="54" y="44" fontFamily="Segoe UI,sans-serif" fontSize="10.5" fill="#80858f">{clip(info.label,20)}</text>
    {n.assetId&&<circle className="node-linked" cx={NODE_W-12} cy="12" r="3.5" fill="#1f9d6b"><title>Linked to an inventory record</title></circle>}
    <title>{n.label+' · '+info.label+(n.assetId?' · linked to inventory (double-click to open)':'')}</title>
   </g>})}
  </svg>
  {interactive&&<div className="graph-controls" role="group" aria-label="Zoom">
   <button type="button" aria-label="Zoom out" title="Zoom out" onClick={()=>zoom(1/1.25)}>−</button>
   <button type="button" className="graph-zoom" title="Fit the whole diagram in view" onClick={()=>setView(null)}>{percent}%</button>
   <button type="button" aria-label="Zoom in" title="Zoom in" onClick={()=>zoom(1.25)}>+</button>
   <button type="button" title="Fit the whole diagram in view" onClick={()=>setView(null)}>Fit</button>
  </div>}
 </div>;
}
