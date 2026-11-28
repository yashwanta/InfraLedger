import {text} from './api';
import {type DiagramEdge,type DiagramNode,type Item} from './model';
import {buildNetworkTree} from './NetworkTree';
import {NODE_H,NODE_W} from './DiagramGraph';

// Builds a topology diagram from discovery: Internet → gateway → subnet →
// switches → devices, using the same placement as the Network tree (switch
// ports from SNMP, otherwise grouped by device type under the subnet).
// Diagrams are limited to 200 components on an 1800 × 1200 canvas, so large
// sets of similar devices are shown as one summary component. Children sit
// below their parent; a parent with several plain devices lists them in
// indented columns, wrapped so the drawing keeps a canvas-friendly shape.

export const AUTO_DIAGRAM_NAME='Network topology (auto)';
const MAX_NODES=150,WIDTH=1800,HEIGHT=1200,LEVEL=NODE_H+64,ROW=NODE_H+18,INDENT=40,GAP=28,LABEL_SPACE=70,VIEW_W=1600,VIEW_H=900;

interface TreeLike {id:string;kind:string;label:string;sub?:string;port?:string;category?:string;recordId?:string;children:TreeLike[];count?:number}

const CATEGORY_KINDS:Record<string,string>={Router:'firewall',Firewall:'firewall',Switch:'switch','Access point':'switch','Network device':'switch',Server:'server',Storage:'server','Virtual machine':'server',Container:'server',UPS:'server',Laptop:'workstation',Desktop:'workstation',Workstation:'workstation',Computer:'workstation',Printer:'printer',Camera:'camera','Phone / tablet':'phone','TV / media device':'media','IoT device':'iot'};
const kindFor=(n:TreeLike)=>n.kind==='subnet'?'cloud':n.kind==='gateway'?'firewall':CATEGORY_KINDS[n.category||'']||'device';

export function buildAutoDiagram(records:Item[],orgId:string):{nodes:DiagramNode[];edges:DiagramEdge[]}{
 const [org]=buildNetworkTree(records,[],orgId) as TreeLike[];
 const nodes:DiagramNode[]=[],edges:DiagramEdge[]=[];
 const add=(n:{id:string;label:string;kind:string;assetId?:string},_depth:number,parent?:string,label=''):boolean=>{
  if(nodes.length>=MAX_NODES)return false;
  nodes.push({...n,x:0,y:0});
  if(parent)edges.push({from:parent,to:n.id,label});
  return true;
 };
 const internet=records.find(r=>r.type==='assets'&&r.orgId===orgId&&r.internetNode);
 const top=internet?'internet':undefined;
 if(internet)add({id:'internet',label:'Internet',kind:'cloud',assetId:internet.id},0);
 // Summarise leaf devices when a parent has many of them.
 const walk=(n:TreeLike,depth:number,parent?:string)=>{
  const id='n'+nodes.length;
  const label=(n.kind==='subnet'?n.label:n.kind==='gateway'&&!n.recordId?(/\d+\.\d+\.\d+\.\d+/.exec(n.label)?.[0]||n.label):n.count!==undefined?`${n.label} (${n.count})`:n.label).slice(0,100);
  if(!add({id,label,kind:kindFor(n),assetId:n.kind==='device'||n.kind==='gateway'?n.recordId:undefined},depth,parent,(n.port||'').slice(0,60)))return;
  const leaves=n.children.filter(c=>c.kind==='device'&&!c.children.length);
  const branches=n.children.filter(c=>!leaves.includes(c));
  for(const c of branches){
   if(c.kind==='group'&&(c.count||0)>4){add({id:'n'+nodes.length,label:`${c.label} (${c.count})`.slice(0,100),kind:kindFor(c.children[0]||c)},depth+1,id);continue}
   if(c.kind==='group'){for(const d of c.children)walk(d,depth+1,id);continue}
   walk(c,depth+1,id);
  }
  if(leaves.length<=6)leaves.forEach(c=>walk(c,depth+1,id));
  else{const byType=new Map<string,TreeLike[]>();for(const l of leaves)byType.set(l.category||'Device',[...(byType.get(l.category||'Device')||[]),l]);for(const [type,list] of byType)add({id:'n'+nodes.length,label:`${type} (${list.length})`.slice(0,100),kind:kindFor(list[0])},depth+1,id)}
 };
 for(const child of org?.children||[]){
  if(child.id.startsWith('o:'))continue; // devices outside documented networks
  walk(child,internet?1:0,top);
 }
 // Tree layout. place() positions a subtree with its left edge at x and returns its width.
 // A parent with many plain devices lists them in columns of at most `rows`; the
 // layout tried last is the one whose shape best fits a wide editor canvas.
 const kids=new Map<string,string[]>(),hasParent=new Set<string>(),labelled=new Set<string>();
 for(const e of edges){if(!kids.has(e.from))kids.set(e.from,[]);kids.get(e.from)!.push(e.to);hasParent.add(e.to);if(e.label)labelled.add(e.from)}
 const pos=new Map<string,{x:number;y:number}>(),listed=new Set<string>();
 const place=(id:string,x:number,y:number,stackFrom:number,rows:number):number=>{
  const children=kids.get(id)||[];
  if(!children.length){pos.set(id,{x,y});return NODE_W}
  const leaves=children.filter(c=>!kids.get(c)?.length),branches=children.filter(c=>kids.get(c)?.length);
  let cursor=x;
  if(leaves.length>=stackFrom){
   pos.set(id,{x,y});
   const perCol=Math.min(rows,leaves.length),cols=Math.ceil(leaves.length/perCol),pitch=NODE_W+(labelled.has(id)?LABEL_SPACE:0)+INDENT;
   leaves.forEach((c,i)=>{pos.set(c,{x:x+INDENT+Math.floor(i/perCol)*pitch,y:y+LEVEL+(i%perCol)*ROW});listed.add(c)});
   cursor=x+INDENT+(cols-1)*pitch+NODE_W+(labelled.has(id)?LABEL_SPACE:0)+GAP;
   for(const b of branches)cursor+=place(b,cursor,y+LEVEL,stackFrom,rows)+GAP;
   return cursor-GAP-x;
  }
  const centers:number[]=[];
  for(const c of [...branches,...leaves]){const w=place(c,cursor,y+LEVEL,stackFrom,rows);centers.push(pos.get(c)!.x+NODE_W/2);cursor+=w+GAP}
  const px=Math.max(x,Math.round((centers[0]+centers[centers.length-1])/2-NODE_W/2));
  pos.set(id,{x:px,y});
  return Math.max(cursor-GAP-x,px-x+NODE_W);
 };
 const roots=nodes.filter(n=>!hasParent.has(n.id)).map(n=>n.id);
 const layout=(stackFrom:number,rows:number)=>{
  pos.clear();listed.clear();let cursor=0;
  for(const r of roots)cursor+=place(r,cursor,0,stackFrom,rows)+GAP;
  const width=Math.max(0,cursor-GAP),height=Math.max(0,...[...pos.values()].map(p=>p.y))+NODE_H;
  return {width,height,pos:new Map(pos),listed:new Set(listed)};
 };
 // Score each candidate by how large it would draw on a 16:9 canvas; drawings that
 // do not fit the stored canvas lose, and ties keep the earlier (wider) candidate.
 const score=(l:{width:number;height:number})=>(l.width<=WIDTH-80&&l.height<=HEIGHT-80?1:0)*10+Math.min(1,VIEW_W/l.width,VIEW_H/l.height);
 let best=layout(Infinity,Infinity);
 for(const stackFrom of [7,5,4,3])for(const rows of [3,4,5,6,8,10,Infinity]){const l=layout(stackFrom,rows);if(score(l)>score(best))best=l}
 const left=Math.max(40,Math.round((WIDTH-best.width)/2));
 for(const n of nodes){const p=best.pos.get(n.id)||{x:0,y:0};n.x=Math.min(WIDTH,left+p.x);n.y=Math.min(HEIGHT,40+p.y)}
 for(const e of edges)if(best.listed.has(e.to))e.route='list';
 return {nodes,edges};
}

export const isAutoDiagram=(d:Item)=>Boolean(d.autoGenerated)||text(d.name)===AUTO_DIAGRAM_NAME;
