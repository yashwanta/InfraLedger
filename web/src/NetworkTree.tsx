import {useEffect,useMemo,useState} from 'react';
import {api,text} from './api';
import {type Item,type User} from './model';
import {Empty,Heading} from './ui';
import {tx} from './i18n';

// Node-link tree of every discovered device.
//
// Organization → collector → gateway → subnet → physical path → device.
// The physical path comes from the SNMP sweep: uplinkAssetId/uplinkPort (the
// switch port a device's MAC is learned on) and lldpNeighbors (switch-to-switch
// links). Those links are undirected facts, so the tree orients them by
// walking outwards from each subnet's gateway. Devices with no known switch
// port are grouped by device type under their subnet.

interface TreeNode {id:string;kind:'org'|'collector'|'gateway'|'subnet'|'group'|'device';label:string;sub?:string;port?:string;category?:string;recordId?:string;children:TreeNode[];count?:number}
interface Collector {id:string;name:string;orgId:string;assetId:string;discovery?:{config?:{cidrs?:string[]}}}
interface Placed {node:TreeNode;key:string;x:number;y:number;depth:number;parent?:Placed}

const ROW=38,COL=250,NODE_W=200,NODE_H=30;

function ipNumber(ip:string){const p=ip.split('.').map(Number);return p.length===4&&p.every(n=>n>=0&&n<=255)?((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3]:-1}
function inCidr(ip:string,cidr:string){const [base,bits]=cidr.split('/'),n=ipNumber(ip),b=ipNumber(base),len=Number(bits);if(n<0||b<0||!(len>=0&&len<=32))return false;const mask=len===0?0:(~0<<(32-len))>>>0;return ((n&mask)>>>0)===((b&mask)>>>0)}
const prefix=(cidr:string)=>Number(cidr.split('/')[1])||0;
const plural:Record<string,string>={'Router':'Routers','Switch':'Switches','Firewall':'Firewalls','Access point':'Access points','Network device':'Network devices','Printer':'Printers','Storage':'Storage','Server':'Servers','Virtual machine':'Virtual machines','Laptop':'Laptops','Desktop':'Desktops','Workstation':'Workstations','Computer':'Computers','Endpoint':'Endpoints','Network endpoint':'Network endpoints'};
const infra=['Router','Switch','Firewall','Access point','Network device'];
const tone=(n:TreeNode)=>n.kind!=='device'&&n.kind!=='gateway'?n.kind:n.category==='Router'||n.category==='Firewall'?'router':n.category==='Switch'||n.category==='Network device'?'switch':n.category==='Access point'?'ap':n.category==='Printer'?'printer':n.category==='Server'||n.category==='Storage'||n.category==='Virtual machine'?'server':'device';

export function buildNetworkTree(records:Item[],collectors:Collector[],orgFilter:string):TreeNode[]{
 const orgs=records.filter(r=>r.type==='organizations'&&(!orgFilter||r.id===orgFilter));
 return orgs.map(org=>{
  const assets=records.filter(r=>r.type==='assets'&&r.orgId===org.id&&!r.internetNode),byId=new Map(assets.map(a=>[a.id,a]));
  const networks=records.filter(r=>r.type==='networks'&&r.orgId===org.id&&text(r.cidr).includes('/')).sort((a,b)=>prefix(text(b.cidr))-prefix(text(a.cidr)));
  const subnetOf=new Map<string,Item>();
  for(const a of assets){const ip=text(a.ip);if(!ip)continue;const n=networks.find(n=>inCidr(ip,text(n.cidr)));if(n)subnetOf.set(a.id,n)}
  // Undirected physical links reported by the SNMP sweep.
  const links=new Map<string,{to:string;port:string}[]>();
  const link=(a:string,b:string,portOnA:string,portOnB:string)=>{if(!byId.has(a)||!byId.has(b)||a===b)return;links.set(a,[...(links.get(a)||[]),{to:b,port:portOnB}]);links.set(b,[...(links.get(b)||[]),{to:a,port:portOnA}])};
  for(const a of assets){
   if(a.uplinkAssetId)link(text(a.uplinkAssetId),a.id,text(a.uplinkPort),'');
   for(const n of (Array.isArray(a.lldpNeighbors)?a.lldpNeighbors:[]) as {assetId?:string;localPort?:string;remotePort?:string}[])link(a.id,text(n.assetId),text(n.localPort),text(n.remotePort));
  }
  // Orient the links by walking out from the gateways, then from the best-connected switches.
  const parent=new Map<string,{id:string;port:string}>(),visited=new Set<string>();
  const gatewayIds=networks.map(n=>assets.find(a=>text(a.ip)&&text(a.ip)===text(n.gateway))?.id).filter(Boolean) as string[];
  const roots=[...gatewayIds,...assets.filter(a=>links.has(a.id)).sort((a,b)=>(links.get(b.id)!.length)-(links.get(a.id)!.length)).map(a=>a.id)];
  for(const root of roots){if(visited.has(root))continue;visited.add(root);const queue=[root];while(queue.length){const at=queue.shift()!;for(const l of links.get(at)||[])if(!visited.has(l.to)){visited.add(l.to);parent.set(l.to,{id:at,port:l.port});queue.push(l.to)}}}
  const childrenOf=new Map<string,string[]>();
  for(const [child,p] of parent)childrenOf.set(p.id,[...(childrenOf.get(p.id)||[]),child]);
  const deviceNode=(a:Item,depth=0):TreeNode=>{
   const kids=(childrenOf.get(a.id)||[]).map(id=>byId.get(id)!).sort(sortDevices);
   return {id:'d:'+a.id,kind:'device',label:a.name,sub:[text(a.ip),text(a.manufacturer)].filter(Boolean).join(' · '),port:parent.get(a.id)?.port,category:text(a.category),recordId:a.id,children:depth>40?[]:kids.map(k=>deviceNode(k,depth+1))};
  };
  const grouped=(prefixId:string,list:Item[]):TreeNode[]=>{
   const byType=new Map<string,Item[]>();
   for(const a of list){const c=text(a.category)||'Unknown';byType.set(c,[...(byType.get(c)||[]),a])}
   return [...byType].sort(([a],[b])=>(infra.includes(b)?1:0)-(infra.includes(a)?1:0)||a.localeCompare(b)).map(([type,items])=>({id:prefixId+':'+type,kind:'group',label:plural[type]||type,count:items.length,children:items.sort(sortDevices).map(a=>deviceNode(a))}));
  };
  const subnetNode=(n:Item):TreeNode=>{
   const gateway=assets.find(a=>text(a.ip)&&text(a.ip)===text(n.gateway));
   const members=assets.filter(a=>subnetOf.get(a.id)?.id===n.id&&a.id!==gateway?.id);
   const top=members.filter(a=>!parent.has(a.id)&&childrenOf.has(a.id));
   const underGateway=gateway?(childrenOf.get(gateway.id)||[]).map(id=>byId.get(id)!):[];
   const loose=members.filter(a=>!parent.has(a.id)&&!childrenOf.has(a.id));
   return {id:'s:'+n.id,kind:'subnet',label:text(n.cidr),sub:n.name!==n.cidr?n.name:text(n.purpose),count:members.length,children:[...[...underGateway,...top].sort(sortDevices).map(a=>deviceNode(a)),...grouped('g:'+n.id,loose)]};
  };
  const gatewayNode=(gatewayIp:string,subnets:Item[]):TreeNode=>{
   const g=assets.find(a=>text(a.ip)===gatewayIp&&gatewayIp);
   return g?{id:'gw:'+g.id+':'+subnets[0].id,kind:'gateway',label:g.name,sub:[text(g.ip),text(g.manufacturer)].filter(Boolean).join(' · '),category:text(g.category)||'Router',recordId:g.id,children:subnets.map(subnetNode)}
    :{id:'gw:none:'+subnets[0].id,kind:'gateway',label:gatewayIp?tx('Gateway')+' '+gatewayIp:tx('No gateway recorded'),sub:gatewayIp?tx('Not discovered yet'):'',children:subnets.map(subnetNode)};
  };
  const byGateway=(list:Item[])=>{const m=new Map<string,Item[]>();for(const n of list)m.set(text(n.gateway),[...(m.get(text(n.gateway))||[]),n]);return [...m].map(([ip,subnets])=>gatewayNode(ip,subnets))};
  // Group subnets under the collector that discovered them.
  const used=networks.filter(n=>assets.some(a=>subnetOf.get(a.id)?.id===n.id));
  const mine=collectors.filter(c=>c.orgId===org.id),claimed=new Set<string>(),children:TreeNode[]=[];
  for(const c of mine){
   const host=byId.get(c.assetId),cidrs=c.discovery?.config?.cidrs||[];
   const subnets=used.filter(n=>!claimed.has(n.id)&&(n.collectorId===c.id||cidrs.includes(text(n.cidr))||(host&&text(host.ip)&&inCidr(text(host.ip),text(n.cidr)))));
   subnets.forEach(n=>claimed.add(n.id));
   if(subnets.length)children.push({id:'c:'+c.id,kind:'collector',label:host?.name||c.name,sub:tx('Collector')+(host?.ip?' · '+text(host.ip):''),recordId:host?.id,children:byGateway(subnets)});
  }
  const rest=used.filter(n=>!claimed.has(n.id));
  children.push(...byGateway(rest));
  const outside=assets.filter(a=>!subnetOf.has(a.id)&&!parent.has(a.id));
  if(outside.length)children.push({id:'o:'+org.id,kind:'group',label:tx('Outside documented networks'),count:outside.length,children:grouped('og:'+org.id,outside)});
  return {id:'org:'+org.id,kind:'org',label:org.name,sub:assets.length+' '+tx('devices'),children};
 });
}
function sortDevices(a:Item,b:Item){const ia=infra.indexOf(text(a.category)),ib=infra.indexOf(text(b.category));return (ia<0?99:ia)-(ib<0?99:ib)||ipNumber(text(a.ip))-ipNumber(text(b.ip))||a.name.localeCompare(b.name)}

function defaultOpen(n:TreeNode):boolean{return n.kind==='org'||n.kind==='collector'||n.kind==='gateway'||n.kind==='subnet'||(n.kind==='device'&&n.children.length>0&&n.children.length<=40)||(n.kind==='group'&&!n.id.startsWith('o')&&!n.id.startsWith('og')&&(n.count||0)<=12)}

export function NetworkTree({records,scope,user,onOpen}:{records:Item[];scope:string;user:User;onOpen:(id:string)=>void}){
 const [collectors,setCollectors]=useState<Collector[]>([]),[open,setOpen]=useState<Record<string,boolean>>({}),[zoom,setZoom]=useState(1),[query,setQuery]=useState('');
 useEffect(()=>{if(user.role==='client')return;api<Collector[]>('/discovery').then(setCollectors).catch(()=>setCollectors([]))},[user.id]);
 const roots=useMemo(()=>buildNetworkTree(records,collectors,scope),[records,collectors,scope]);
 const q=query.trim().toLowerCase();
 // Search opens every ancestor of a match.
 const forced=useMemo(()=>{const s=new Set<string>();if(!q)return s;const walk=(n:TreeNode,path:string[]):boolean=>{let hit=false;for(const c of n.children)if(walk(c,[...path,n.id]))hit=true;const self=n.kind==='device'&&(n.label.toLowerCase().includes(q)||(n.sub||'').toLowerCase().includes(q));if(hit)s.add(n.id);return hit||self};roots.forEach(r=>walk(r,[]));return s},[roots,q]);
 const isOpen=(n:TreeNode)=>forced.has(n.id)||(open[n.id]??defaultOpen(n));
 const placed:Placed[]=[];let row=0;
 const layout=(n:TreeNode,depth:number,parent?:Placed):Placed=>{const p:Placed={node:n,key:(parent?parent.key+'/':'')+n.id,x:depth*COL,y:0,depth,parent};placed.push(p);const kids=isOpen(n)?n.children:[];if(!kids.length){p.y=row*ROW;row++}else{const ys=kids.map(k=>layout(k,depth+1,p).y);p.y=(ys[0]+ys[ys.length-1])/2}return p};
 roots.forEach(r=>{layout(r,0);row++});
 const width=Math.max(...placed.map(p=>p.x),0)+NODE_W+40,height=Math.max(row*ROW,ROW)+20;
 const devices=records.filter(r=>r.type==='assets'&&!r.internetNode&&(!scope||r.orgId===scope)),onPorts=devices.filter(d=>d.uplinkAssetId).length,networkGear=devices.filter(d=>infra.includes(text(d.category))).length;
 const setAll=(value:boolean)=>{const next:Record<string,boolean>={};const walk=(n:TreeNode)=>{if(n.children.length)next[n.id]=value||n.kind==='org';n.children.forEach(walk)};roots.forEach(walk);setOpen(next)};
 const toggle=(n:TreeNode)=>setOpen(o=>({...o,[n.id]:!isOpen(n)}));
 const activate=(n:TreeNode)=>{if(n.recordId&&n.kind!=='collector')onOpen(n.recordId);else if(n.children.length)toggle(n)};
 const match=(n:TreeNode)=>q&&n.kind==='device'&&(n.label.toLowerCase().includes(q)||(n.sub||'').toLowerCase().includes(q));
 return <>
  <Heading title={tx('Network tree')} sub={tx('Every discovered device, from gateway and subnet down to the switch port it is plugged into.')}>
   <input className="tree-search" aria-label="Find a device" placeholder="Find a device…" value={query} onChange={e=>setQuery(e.target.value)}/>
   <button onClick={()=>setAll(true)}>Expand all</button><button onClick={()=>setAll(false)}>Collapse all</button>
   <div className="zoom-controls"><button aria-label="Zoom out" onClick={()=>setZoom(z=>Math.max(.4,+(z-.1).toFixed(1)))}>−</button><span>{Math.round(zoom*100)}%</span><button aria-label="Zoom in" onClick={()=>setZoom(z=>Math.min(1.6,+(z+.1).toFixed(1)))}>+</button></div>
  </Heading>
  <div className="tree-stats"><span><b>{devices.length}</b> <span>devices</span></span><span><b>{networkGear}</b> <span>network devices</span></span><span><b>{onPorts}</b> <span>placed on switch ports</span></span>
   <span className="tree-legend">{(['router','switch','ap','server','printer','device'] as const).map(k=><span key={k}><i className={'dot tone-'+k}/>{{router:'Router / firewall',switch:'Switch',ap:'Access point',server:'Server / storage',printer:'Printer',device:'Other device'}[k]}</span>)}</span></div>
  {!devices.length?<Empty title="No discovered devices yet">Install a collector or add an SNMP credential under Setup → Integrations to discover your network.</Empty>:
  <div className="tree-canvas"><svg width={width*zoom} height={height*zoom} viewBox={`0 0 ${width} ${height}`} role="tree" aria-label="Network tree">
   {placed.filter(p=>p.parent).map(p=>{const a=p.parent!,x1=a.x+NODE_W,y1=a.y+NODE_H/2,x2=p.x,y2=p.y+NODE_H/2,mid=(x1+x2)/2;return <g key={'e'+p.key}><path className="tree-edge" d={`M${x1} ${y1}C${mid} ${y1} ${mid} ${y2} ${x2} ${y2}`}/>{p.node.port&&<text className="tree-port" x={x2-6} y={y2-5} textAnchor="end" data-no-translate>{p.node.port}</text>}</g>})}
   {placed.map(p=>{const n=p.node,has=n.children.length>0,opened=isOpen(n);return <g key={p.key} className={'tree-node tone-'+tone(n)+(match(n)?' match':'')} transform={`translate(${p.x} ${p.y})`} role="treeitem" aria-expanded={has?opened:undefined} tabIndex={0} onClick={()=>activate(n)} onKeyDown={e=>{if(e.key==='Enter')activate(n);if(e.key===' '&&has){e.preventDefault();toggle(n)}}}>
    <rect width={NODE_W} height={NODE_H} rx={7}/><rect className="tree-accent" width={4} height={NODE_H} rx={2}/>
    <text x={12} y={n.sub?13:19} className="tree-label" data-no-translate={n.kind==='device'||n.kind==='subnet'||n.kind==='org'||n.kind==='collector'?'':undefined}>{n.label.length>26?n.label.slice(0,25)+'…':n.label}{n.count!==undefined&&<tspan className="tree-count"> {n.count}</tspan>}</text>
    {n.sub&&<text x={12} y={25} className="tree-sub" data-no-translate>{n.sub.length>34?n.sub.slice(0,33)+'…':n.sub}</text>}
    {has&&<g className="tree-toggle" onClick={e=>{e.stopPropagation();toggle(n)}}><circle cx={NODE_W} cy={NODE_H/2} r={8}/><text x={NODE_W} y={NODE_H/2+4} textAnchor="middle" data-no-translate>{opened?'−':'+'}</text></g>}
    <title>{[n.label,n.sub,n.category,n.port?tx('Switch port')+': '+n.port:''].filter(Boolean).join('\n')}</title>
   </g>})}
  </svg></div>}
 </>;
}
