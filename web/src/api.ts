import {type Item,type User,canView,canEdit} from './model';
let csrf='';
export const setCSRF=(value:string)=>{csrf=value};
export async function api<T=Record<string,unknown>>(path:string,method='GET',body?:unknown):Promise<T>{const response=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});const data=await response.json();if(!response.ok)throw Object.assign(new Error(data.error||'Request failed'),{status:response.status});return data as T}
export interface Session {user:User;csrf:string}
export interface Status {setupRequired:boolean;setupCodeRequired?:boolean;timeZone:string;backend:string;frontend:string}
export const getRecords=async()=>{const [records,context]=await Promise.all([api<Item[]>('/records'),api<{organizations:Item[]}>('/context')]);return [...records,...context.organizations.filter(o=>!records.some(r=>r.id===o.id)).map(o=>({...o,version:0,created:'',updated:''}))]};
export function download(content:string,name:string,type='application/json'){const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([content],{type}));link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000)}
export const text=(value:unknown)=>value==null?'':String(value);
export let zone='America/New_York';export const setZone=(s:string)=>{zone=s};
export const date=(s:unknown)=>s?new Date(text(s).includes('T')?text(s):text(s)+'T12:00:00Z').toLocaleDateString(undefined,{timeZone:zone,month:'short',day:'numeric',year:'numeric'}):'—';
export const when=(s:unknown)=>new Date(typeof s==='number'?s:text(s)).toLocaleString(undefined,{timeZone:zone});
export const days=(s:string)=>{const today=new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());return Math.round((+new Date(s+'T12:00:00Z')-+new Date(today+'T12:00:00Z'))/86400000)};
export const money=(n:unknown,c='USD')=>{try{return new Intl.NumberFormat(undefined,{style:'currency',currency:c}).format(Number(n)||0)}catch{return c+' '+text(n)}};
export const writable=(u:User,page?:string)=>page?canEdit(u,page):u.role==='admin'||Object.values(u.pageAccess||u.permissions||{}).includes('edit')||['editor','it_analyst','plant_it'].includes(u.role);
export {canView,canEdit};
