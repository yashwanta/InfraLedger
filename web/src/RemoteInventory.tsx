import {useEffect,useState,type FormEvent} from 'react';
import {type Item,type User} from './model';
import {api,text,when} from './api';
import {Badge,Empty,Modal,Panel} from './ui';

export interface Credential {id:string;name:string;kind:'ssh'|'winrm';username:string;port:number;orgId:string;hasSecret:boolean;created?:string}
interface Scan {id:string;assetId:string;credentialId:string;status:string;requested:string;finished?:string;summary:{error?:string;hostname?:string;os?:string;software?:number;services?:number;interfaces?:number}}

const kindLabel=(k:string)=>k==='winrm'?'WinRM (Windows)':'SSH (Linux)';
const scanDetail=(s:Scan)=>s.status==='Completed'?`${text(s.summary.os)||'OS not reported'} · ${s.summary.software??0} software · ${s.summary.services??0} services`:s.summary.error||'';

/** Setup → Integrations: saved SSH / WinRM credentials and recent remote scans. */
export function RemoteCredentials({records,user,onError}:{records:Item[];user:User;onError:(s:string)=>void}){
 const [rows,setRows]=useState<Credential[]>([]),[scans,setScans]=useState<Scan[]>([]),[editing,setEditing]=useState<Partial<Credential>>(),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const admin=user.role==='admin';
 const load=async()=>{if(!admin)return;const [c,s]=await Promise.all([api<Credential[]>('/remote-inventory/credentials'),api<Scan[]>('/remote-inventory/scans')]);setRows(c);setScans(s)};
 useEffect(()=>{load().catch(e=>onError(e.message));if(!admin)return;const t=setInterval(()=>load().catch(()=>{}),5000);return()=>clearInterval(t)},[user.id]);
 const orgs=records.filter(r=>r.type==='organizations'),name=(id:unknown)=>records.find(r=>r.id===id)?.name||'—';
 async function save(e:FormEvent<HTMLFormElement>){e.preventDefault();setBusy(true);setError('');try{const v=Object.fromEntries(new FormData(e.currentTarget));await api('/remote-inventory/credentials'+(editing?.id?'/'+editing.id:''),editing?.id?'PUT':'POST',{...v,orgId:editing?.orgId||v.orgId,kind:editing?.kind,port:Number(v.port)||0});setEditing(undefined);await load()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function remove(c:Credential){try{await api('/remote-inventory/credentials/'+c.id,'DELETE',{});await load()}catch(e){onError((e as Error).message)}}
 return <Panel title="Remote inventory — Windows & Linux without a collector" action={admin?<button className="primary" onClick={()=>{setError('');setEditing({kind:'ssh',orgId:orgs[0]?.id,port:22})}}>Add credential</button>:undefined}><div style={{padding:24}}>
  <p>Sign in to devices that have no collector and read their system details: host name, OS, manufacturer, model and serial, network interfaces, installed software and running services. Commands are read-only.</p>
  <p>Use a dedicated low-privilege account. <strong>Linux:</strong> SSH with password or key. <strong>Windows:</strong> WinRM (run <code>winrm quickconfig</code> on the device; TCP 5985) with an account in the local <em>Remote Management Users</em> group. Devices must have a private IP inside the organization's networks or discovery subnets. Start a scan from a device's page or from Auto Discovery.</p>
  {!admin?<p>Ask your IT Admin to configure remote inventory.</p>:rows.length?<div className="table-scroll"><table><thead><tr><th>Credential</th><th>Type</th><th>User</th><th>Organization</th><th></th></tr></thead><tbody>{rows.map(c=><tr key={c.id}><td><strong>{c.name}</strong></td><td><Badge value={kindLabel(c.kind)}/> <small>port {c.port}</small></td><td>{c.username}</td><td>{name(c.orgId)}</td><td><div className="actions"><button onClick={()=>{setError('');setEditing({...c})}}>Edit</button><button onClick={()=>remove(c)}>Delete</button></div></td></tr>)}</tbody></table></div>:<Empty title="No remote inventory credentials yet">Add an SSH or WinRM credential to inventory devices without installing a collector.</Empty>}
  {admin&&scans.length>0&&<><h3 style={{marginTop:24}}>Recent remote scans</h3><div className="table-scroll"><table><thead><tr><th>Device</th><th>Status</th><th>Result</th><th>Finished</th></tr></thead><tbody>{scans.slice(0,15).map(s=><tr key={s.id}><td>{name(s.assetId)}</td><td><Badge value={s.status}/></td><td><small>{scanDetail(s)}</small></td><td>{s.finished?when(s.finished):'—'}</td></tr>)}</tbody></table></div></>}
 </div>
 {editing&&<Modal title={editing.id?'Edit remote inventory credential':'Add remote inventory credential'} onClose={()=>setEditing(undefined)}><form onSubmit={save}>
  <div className="notice">The password or key is encrypted on this server and never shown again. Leave it blank when editing to keep the saved one.</div>
  <div className="form-grid">
   <label className="form-field">Name<input name="name" required maxLength={120} defaultValue={editing.name} placeholder="e.g. Linux servers – inventory"/></label>
   <label className="form-field">Organization<select name="orgId" required disabled={Boolean(editing.id)} value={editing.orgId||''} onChange={e=>setEditing({...editing,orgId:e.target.value})}><option value="">Select organization</option>{orgs.map(o=><option key={o.id} value={o.id}>{o.name}</option>)}</select></label>
   <label className="form-field">Type<select value={editing.kind} onChange={e=>setEditing({...editing,kind:e.target.value as Credential['kind'],port:e.target.value==='winrm'?5985:22})}><option value="ssh">SSH (Linux)</option><option value="winrm">WinRM (Windows)</option></select></label>
   <label className="form-field">Port<input name="port" type="number" min={1} max={65535} value={editing.port||''} onChange={e=>setEditing({...editing,port:Number(e.target.value)})}/></label>
   <label className="form-field">User name<input name="username" required autoComplete="off" defaultValue={editing.username} placeholder={editing.kind==='winrm'?'DOMAIN\\svc-inventory or .\\inventory':'inventory'}/></label>
   <label className="form-field">Password<input name="password" type="password" autoComplete="new-password" required={!editing.id&&editing.kind==='winrm'} placeholder={editing.id?'Leave blank to keep saved secret':''}/></label>
   {editing.kind==='ssh'&&<label className="form-field full">SSH private key (optional, instead of a password)<textarea name="privateKey" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"/><small>Unencrypted OpenSSH or PEM key. The first host key seen for each device is remembered; a changed key blocks scanning until you reset it on the device page.</small></label>}
  </div>
  {error&&<div className="form-error">{error}</div>}
  <div className="form-actions"><button type="button" onClick={()=>setEditing(undefined)}>Cancel</button><button className="primary" disabled={busy}>{busy?'Saving…':'Save credential'}</button></div>
 </form></Modal>}
 </Panel>
}

/** Device page: run a remote scan for one asset and show its latest result. */
export function RemoteScanAction({record,user,onReload}:{record:Item;user:User;onReload:()=>Promise<void>|void}){
 const [creds,setCreds]=useState<Credential[]>([]),[choice,setChoice]=useState(''),[scans,setScans]=useState<Scan[]>([]),[error,setError]=useState('');
 const admin=user.role==='admin',ip=text(record.ip);
 const load=async()=>{const [c,s]=await Promise.all([api<Credential[]>('/remote-inventory/credentials'),api<Scan[]>('/remote-inventory/scans?assetId='+record.id)]);const mine=c.filter(x=>x.orgId===record.orgId);setCreds(mine);setChoice(v=>v||mine[0]?.id||'');setScans(s)};
 const active=scans[0]&&['Queued','Running'].includes(scans[0].status);
 useEffect(()=>{if(!admin||!ip)return;load().catch(()=>{})},[record.id]);
 useEffect(()=>{if(!active)return;const t=setInterval(async()=>{await load().catch(()=>{});},3000);return()=>clearInterval(t)},[active]);
 useEffect(()=>{if(scans[0]?.status==='Completed')Promise.resolve(onReload()).catch(()=>{})},[scans[0]?.id,scans[0]?.status]);
 if(!admin||!ip||record.type!=='assets')return null;
 const last=scans[0];
 const run=async()=>{setError('');try{const r=await api<{queued:number;rejected:{error:string}[]}>('/remote-inventory/scan','POST',{credentialId:choice,assetIds:[record.id]});if(!r.queued)setError(r.rejected[0]?.error||'Scan was not queued');await load()}catch(e){setError((e as Error).message)}};
 const reset=async()=>{try{await api('/remote-inventory/trust/'+record.id,'DELETE',{});setError('Trusted identity cleared. The next scan will remember the new host key.')}catch(e){setError((e as Error).message)}};
 return <section className="notice"><strong>Remote inventory</strong>
  {creds.length?<div className="actions" style={{marginTop:8}}><select aria-label="Remote inventory credential" value={choice} onChange={e=>setChoice(e.target.value)}>{creds.map(c=><option key={c.id} value={c.id}>{c.name} · {kindLabel(c.kind)}</option>)}</select><button className="primary" disabled={!choice||Boolean(active)} onClick={run}>{active?'Collecting…':'Collect details remotely'}</button></div>:<p>Add an SSH or WinRM credential for this organization under Setup → Integrations to collect details from {ip}.</p>}
  {last&&<p><Badge value={last.status}/> {scanDetail(last)}{last.finished?` · ${when(last.finished)}`:''}</p>}
  {last?.summary.error?.includes('host key changed')&&<button onClick={reset}>Reset trusted identity</button>}
  {error&&<div className="form-error">{error}</div>}
 </section>
}

/** Auto Discovery: queue remote scans for many devices at once. */
export function RemoteBulkScan({assets,user,onError}:{assets:Item[];user:User;onError:(s:string)=>void}){
 const [open,setOpen]=useState(false),[creds,setCreds]=useState<Credential[]>([]),[choice,setChoice]=useState(''),[result,setResult]=useState('');
 if(user.role!=='admin')return null;
 const start=async()=>{setResult('');try{const c=await api<Credential[]>('/remote-inventory/credentials');setCreds(c);setChoice(c[0]?.id||'');setOpen(true)}catch(e){onError((e as Error).message)}};
 const cred=creds.find(c=>c.id===choice),targets=assets.filter(a=>a.ip&&cred&&a.orgId===cred.orgId);
 const run=async()=>{try{const r=await api<{queued:number;rejected:unknown[]}>('/remote-inventory/scan','POST',{credentialId:choice,assetIds:targets.slice(0,256).map(a=>a.id)});setResult(`${r.queued} scans queued${r.rejected.length?`, ${r.rejected.length} skipped (outside documented networks or already queued)`:''}. Results appear on each device and under Setup → Integrations.`)}catch(e){setResult((e as Error).message)}};
 return <><button onClick={start}>Collect details remotely</button>{open&&<Modal title="Collect details remotely" onClose={()=>setOpen(false)}>
  {creds.length?<><p>Sign in to the devices listed in this view with a saved credential and read their system details. Only devices with an IP address in the credential's organization are included.</p><label className="form-field">Credential<select value={choice} onChange={e=>setChoice(e.target.value)}>{creds.map(c=><option key={c.id} value={c.id}>{c.name} · {kindLabel(c.kind)}</option>)}</select></label><p>{targets.length} device{targets.length===1?'':'s'} will be scanned{targets.length>256?' (first 256)':''}.</p>{result&&<div className="notice">{result}</div>}<div className="form-actions"><button onClick={()=>setOpen(false)}>Close</button><button className="primary" disabled={!targets.length||Boolean(result)} onClick={run}>Start scans</button></div></>:<p>Add an SSH or WinRM credential under Setup → Integrations first.</p>}
 </Modal>}</>
}
