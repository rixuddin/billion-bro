const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
async function kdf(pw,salt){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256));}
async function mkHash(pw){const s=rnd(16);return hex(s)+'$'+await kdf(pw,s);}
async function check(pw,stored){const [s,h]=stored.split('$');const t=await kdf(pw,unhex(s));let d=0;for(let i=0;i<h.length;i++)d|=h.charCodeAt(i)^t.charCodeAt(i);return d===0&&h.length===t.length;}
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
const recCode=()=>{const a='ABCDEFGHJKMNPQRSTUVWXYZ23456789',b=rnd(12);let s='';for(let i=0;i<12;i++){s+=a[b[i]%a.length];if(i===3||i===7)s+='-';}return s;};
const okUser=u=>typeof u==='string'&&/^[A-Za-z0-9_.@+-]{3,60}$/.test(u);
const okPw=p=>typeof p==='string'&&p.length>=8&&p.length<=200;
async function session(env,uid){const t=hex(rnd(32));await env.DB.prepare('INSERT INTO sessions(token,user_id,created) VALUES(?,?,?)').bind(await sha(t),uid,Date.now()).run();return t;}
async function who(req,env){const a=req.headers.get('authorization')||'';const t=a.startsWith('Bearer ')?a.slice(7):'';if(!/^[0-9a-f]{64}$/.test(t))return null;return env.DB.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').bind(await sha(t)).first();}
async function api(req,env,p){
 const db=env.DB,now=Date.now();let b={};if(req.method==='POST'){try{b=await req.json();}catch(e){return J({error:'Bad request.'},400);}}
 if(p==='signup'){const u=b.u,pw=b.p;if(!okUser(u))return J({error:'Usernames can be 3 to 60 characters: letters, numbers, or an email address.'},400);if(!okPw(pw))return J({error:'Passwords need at least 8 characters.'},400);
  if(await db.prepare('SELECT 1 FROM users WHERE username=?').bind(u).first())return J({error:'That username is taken.'},409);
  const rc=recCode();const r=await db.prepare('INSERT INTO users(username,pw,rec,created) VALUES(?,?,?,?)').bind(u,await mkHash(pw),await mkHash(rc),now).run();
  const id=r.meta.last_row_id;return J({token:await session(env,id),user:u,recovery:rc});}
 if(p==='login'){const x=await db.prepare('SELECT * FROM users WHERE username=?').bind(String(b.u||'')).first();
  if(!x||!okPw(b.p))return J({error:'Wrong username or password.'},401);
  if(x.locked_until>now)return J({error:'Too many tries. Wait 15 minutes and try again.'},429);
  if(!await check(b.p,x.pw)){const f=x.fails+1;await db.prepare('UPDATE users SET fails=?,locked_until=? WHERE id=?').bind(f>=8?0:f,f>=8?now+900000:0,x.id).run();return J({error:'Wrong username or password.'},401);}
  await db.prepare('UPDATE users SET fails=0 WHERE id=?').bind(x.id).run();return J({token:await session(env,x.id),user:x.username});}
 if(p==='reset'){const x=await db.prepare('SELECT * FROM users WHERE username=?').bind(String(b.u||'')).first();const code=String(b.code||'').toUpperCase().replace(/[^A-Z0-9]/g,'').replace(/^(.{4})(.{4})(.{4})$/,'$1-$2-$3');
  if(!x)return J({error:'Wrong username or recovery code.'},401);if(x.locked_until>now)return J({error:'Too many tries. Wait 15 minutes and try again.'},429);
  if(!await check(code,x.rec)){const f=x.fails+1;await db.prepare('UPDATE users SET fails=?,locked_until=? WHERE id=?').bind(f>=8?0:f,f>=8?now+900000:0,x.id).run();return J({error:'Wrong username or recovery code.'},401);}
  if(!okPw(b.p))return J({error:'Passwords need at least 8 characters.'},400);
  const rc=recCode();await db.prepare('UPDATE users SET pw=?,rec=?,fails=0 WHERE id=?').bind(await mkHash(b.p),await mkHash(rc),x.id).run();await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(x.id).run();
  return J({token:await session(env,x.id),user:x.username,recovery:rc});}
 const me=await who(req,env);if(!me)return J({error:'Please sign in again.'},401);
 if(p==='me'){const s=await db.prepare('SELECT week,nw,updated FROM saves WHERE user_id=?').bind(me.id).first();return J({user:me.username,save:s||null});}
 if(p==='load'){const s=await db.prepare('SELECT data,updated FROM saves WHERE user_id=?').bind(me.id).first();return J(s||{data:null});}
 if(p==='save'){if(typeof b.data!=='string'||b.data.length>1800000)return J({error:'Save is too big.'},413);
  await db.prepare('INSERT INTO saves(user_id,data,week,nw,updated) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,week=excluded.week,nw=excluded.nw,updated=excluded.updated').bind(me.id,b.data,+b.week||0,+b.nw||0,now).run();return J({ok:true,updated:now});}
 if(p==='logout'){const t=(req.headers.get('authorization')||'').slice(7);await db.prepare('DELETE FROM sessions WHERE token=?').bind(await sha(t)).run();return J({ok:true});}
 if(p==='delete'){const x=await db.prepare('SELECT pw FROM users WHERE id=?').bind(me.id).first();if(!okPw(b.p)||!await check(b.p,x.pw))return J({error:'Wrong password.'},401);
  await db.batch([db.prepare('DELETE FROM saves WHERE user_id=?').bind(me.id),db.prepare('DELETE FROM sessions WHERE user_id=?').bind(me.id),db.prepare('DELETE FROM users WHERE id=?').bind(me.id)]);return J({ok:true});}
 return J({error:'Not found.'},404);}
export default{async fetch(req,env){const u=new URL(req.url);
 if(u.pathname.startsWith('/api/')){try{return await api(req,env,u.pathname.slice(5));}catch(e){return J({error:'Server error. Try again.'},500);}}
 return env.ASSETS.fetch(req);}};
