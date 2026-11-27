import {useEffect,useState,type FormEvent} from 'react';
import {api,type Session} from './api';
import {Panel} from './ui';
import type {User} from './model';

// Shown instead of the workspace when the security policy requires MFA and
// the signed-in user has not enrolled yet.
export function MfaRequired({user,onDone,onSignOut}:{user:User;onDone:(s:Session)=>void;onSignOut:()=>void}){
 const [seed,setSeed]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function submit(e:FormEvent<HTMLFormElement>){e.preventDefault();setBusy(true);setError('');const data=Object.fromEntries(new FormData(e.currentTarget));try{if(!seed){setSeed((await api<{seed:string}>('/mfa/start','POST',{password:data.password})).seed)}else{await api('/mfa/confirm','POST',{code:data.code});onDone(await api<Session>('/me'))}}catch(err){setError((err as Error).message)}finally{setBusy(false)}}
 return <div className="auth-screen"><div className="auth-form-wrap" style={{margin:'0 auto'}}><form className="auth-form" onSubmit={submit} key={seed?'confirm':'start'}>
  <h2>Set up authenticator MFA</h2>
  <p className="subtitle">Your organization requires a six-digit authenticator code for {user.role==='admin'?'administrators':'accounts that can reveal vault credentials'}. Set it up to continue, {user.name}.</p>
  {!seed?<label className="form-field">Your account password<input name="password" type="password" required autoComplete="current-password"/></label>:<>
   <div className="notice">Add this setup key to your authenticator app (Microsoft Authenticator, Google Authenticator, 1Password …) as a time-based, six-digit account. Keep it private.</div>
   <div className="code-block">{seed}</div>
   <label className="form-field">Authenticator code<input name="code" required pattern="[0-9]{6}" inputMode="numeric" maxLength={6} autoComplete="one-time-code"/></label></>}
  {error&&<div className="form-error">{error}</div>}
  <button className="primary" disabled={busy}>{busy?'Please wait…':seed?'Enable MFA':'Continue'}</button>
  <button type="button" className="text-button" onClick={onSignOut}>Sign out</button>
 </form></div></div>
}

export function SecurityPolicy({user,onError}:{user:User;onError:(m:string)=>void}){
 const [policy,setPolicy]=useState<{requireMfa:boolean}>(),[busy,setBusy]=useState(false);
 useEffect(()=>{api<{requireMfa:boolean}>('/settings/security').then(setPolicy).catch(e=>onError(e.message))},[]);
 if(!policy)return null;
 const admin=user.role==='admin';
 return <Panel title="Sign-in security"><div style={{padding:24}}>
  <label className="check-label"><input type="checkbox" checked={policy.requireMfa} disabled={!admin||busy} onChange={async e=>{setBusy(true);try{setPolicy(await api('/settings/security','PUT',{requireMfa:e.target.checked}))}catch(err){onError((err as Error).message)}finally{setBusy(false)}}}/>Require authenticator MFA for administrators and vault editors</label>
  <p className="subtitle" style={{marginTop:12}}>When on, these accounts must set up MFA at their next sign-in before they can use InfraLedger. {admin&&!user.mfa?'Set up MFA on your own account first.':''}</p>
 </div></Panel>
}
