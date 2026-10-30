export interface AuthEnv {
  DB: D1Database;
  BOOTSTRAP_SECRET: string;
  ALLOWED_ORIGIN: string;
  LOGIN_RATE_LIMITER: { limit: (input: { key: string }) => Promise<{ success: boolean }> };
}
type User = { id:string; email:string; display_name:string; role:string; is_active:number; organization_id:string };
const COOKIE = "sx_session";
const TTL = 4 * 60 * 60;
const enc = new TextEncoder();
const b64 = (b:Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64 = (s:string) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const id = () => crypto.randomUUID();
async function sha(value:string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(value)))); }
async function passwordHash(password:string) {
  const salt=crypto.getRandomValues(new Uint8Array(16)), iterations=310000;
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations},key,256));
  return `pbkdf2-sha256$${iterations}$${b64(salt)}$${b64(bits)}`;
}
async function passwordVerify(password:string, encoded:string) {
  try {
    const [alg,it,salt,expected]=encoded.split("$"), iterations=Number(it);
    if(alg!=="pbkdf2-sha256"||!Number.isInteger(iterations)||iterations<100000||iterations>1000000) return false;
    const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
    const actual=new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:unb64(salt),iterations},key,256));
    const want=unb64(expected); if(actual.length!==want.length) return false;
    let diff=0; for(let i=0;i<actual.length;i++) diff|=actual[i]^want[i]; return diff===0;
  } catch { return false; }
}
function response(data:unknown,status=200,headers:HeadersInit={}) {
  return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...headers}});
}
function cookie(token:string,age:number) { return `${COOKIE}=${token}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`; }
function tokenFrom(req:Request) {
  return (req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1)||"";
}
export async function currentUser(req:Request, env:AuthEnv):Promise<User|null> {
  const token=tokenFrom(req); if(!token) return null;
  const tokenHash=await sha(token);
  const row=await env.DB.prepare(`SELECT u.id,u.email,u.display_name,m.role,u.is_active,m.organization_id
    FROM auth_sessions s JOIN users u ON u.id=s.user_id
    JOIN organization_memberships m ON m.user_id=u.id
    JOIN organizations o ON o.id=m.organization_id AND o.is_active=1
    WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?
    ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END LIMIT 1`)
    .bind(tokenHash,new Date().toISOString()).first<User>();
  return row && row.is_active===1 ? row : null;
}
async function log(env:AuthEnv,userId:string|null,event:string) {
  await env.DB.prepare("INSERT INTO auth_audit_log(id,user_id,event) VALUES(?,?,?)").bind(id(),userId,event).run();
}
export async function handleAuthRoute(req:Request,env:AuthEnv,path:string):Promise<Response|null> {
  if(path==="/api/auth/bootstrap-status" && req.method==="GET") {
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{n:number}>();
    return response({bootstrapAvailable:(count?.n||0)===0});
  }
  if(path==="/api/auth/bootstrap" && req.method==="POST") {
    if(req.headers.get("Origin") && req.headers.get("Origin")!==env.ALLOWED_ORIGIN) return response({error:"Origin not allowed"},403);
    const ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if(!(await env.LOGIN_RATE_LIMITER.limit({key:"bootstrap:"+ip})).success) return response({error:"Too many setup attempts"},429);
    if(!env.BOOTSTRAP_SECRET || req.headers.get("X-SentinelX-Bootstrap")!==env.BOOTSTRAP_SECRET) return response({error:"Forbidden"},403);
    if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) return response({error:"JSON required"},415);
    const length=Number(req.headers.get("Content-Length"));
    if(Number.isFinite(length)&&length>4096) return response({error:"Request too large"},413);
    let body:{email?:string;name?:string;password?:string;organization?:string};
    try { body=await req.json() as typeof body; } catch { return response({error:"Invalid JSON"},400); }
    const email=body.email?.trim().toLowerCase()||"", name=body.name?.trim()||"", password=body.password||"", org=body.organization?.trim()||"SentinelX";
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||name.length<2||password.length<14||password.length>256) return response({error:"Valid email, name and password (14+ characters) are required"},400);
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{n:number}>();
    if((count?.n||0)>0) return response({error:"Bootstrap is already closed"},409);
    const userId=id(), orgId=id(), slug="sentinelx-"+crypto.randomUUID().slice(0,8);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO organizations(id,name,slug) VALUES(?,?,?)").bind(orgId,org,slug),
      env.DB.prepare("INSERT INTO users(id,email,display_name,password_hash,role) VALUES(?,?,?,?,?)").bind(userId,email,name,await passwordHash(password),"admin"),
      env.DB.prepare("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES(?,?,?)").bind(orgId,userId,"owner")
    ]);
    await log(env,userId,"bootstrap_admin_created");
    return response({created:true,message:"Initial organization administrator created"},201);
  }
  if(path==="/api/auth/login" && req.method==="POST") {
    if(req.headers.get("Origin")!==env.ALLOWED_ORIGIN) return response({error:"Origin not allowed"},403);
    const ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if(!(await env.LOGIN_RATE_LIMITER.limit({key:"login:"+ip})).success) return response({error:"Too many login attempts. Try again in one minute."},429);
    if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) return response({error:"JSON required"},415);
    const length=Number(req.headers.get("Content-Length"));
    if(Number.isFinite(length)&&length>4096) return response({error:"Request too large"},413);
    let body:{email?:string;password?:string};
    try { body=await req.json() as typeof body; } catch { return response({error:"Invalid JSON"},400); }
    const email=body.email?.trim().toLowerCase()||"", password=body.password||"";
    if(email.length>254||password.length>256) return response({error:"Invalid credentials"},401);
    const row=await env.DB.prepare("SELECT id,email,display_name,password_hash,is_active FROM users WHERE email=?").bind(email).first<User&{password_hash:string}>();
    if(!row||row.is_active!==1||!(await passwordVerify(password,row.password_hash))) {
      await log(env,row?.id||null,"login_failed"); return response({error:"Invalid credentials"},401);
    }
    const token=b64(crypto.getRandomValues(new Uint8Array(32))), tokenHash=await sha(token), sessionId=id();
    const expires=new Date(Date.now()+TTL*1000).toISOString();
    await env.DB.prepare("INSERT INTO auth_sessions(id,user_id,token_hash,expires_at,user_agent) VALUES(?,?,?,?,?)")
      .bind(sessionId,row.id,tokenHash,expires,(req.headers.get("User-Agent")||"").slice(0,300)).run();
    await env.DB.prepare("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?").bind(new Date().toISOString(),new Date().toISOString(),row.id).run();
    await log(env,row.id,"login_success");
    return response({authenticated:true,user:{id:row.id,email:row.email,name:row.display_name}},200,{"Set-Cookie":cookie(token,TTL)});
  }
  if(path==="/api/auth/password" && req.method==="POST") {
    if(req.headers.get("Origin")!==env.ALLOWED_ORIGIN) return response({error:"Origin not allowed"},403);
    const actor=await currentUser(req,env); if(!actor) return response({error:"Authentication required"},401);
    if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) return response({error:"JSON required"},415);
    const length=Number(req.headers.get("Content-Length"));
    if(Number.isFinite(length)&&length>4096) return response({error:"Request too large"},413);
    let body:{currentPassword?:string;newPassword?:string};
    try { body=await req.json() as typeof body; } catch { return response({error:"Invalid JSON"},400); }
    const current=body.currentPassword||"", next=body.newPassword||"";
    if(next.length<14||next.length>256) return response({error:"New password must be at least 14 characters"},400);
    const row=await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND is_active=1").bind(actor.id).first<{password_hash:string}>();
    if(!row||!(await passwordVerify(current,row.password_hash))) return response({error:"Current password is incorrect"},401);
    const tokenHash=await sha(tokenFrom(req));
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET password_hash=?,updated_at=? WHERE id=?").bind(await passwordHash(next),new Date().toISOString(),actor.id),
      env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND token_hash<>? AND revoked_at IS NULL").bind(new Date().toISOString(),actor.id,tokenHash)
    ]);
    await log(env,actor.id,"password_changed");
    return response({changed:true,message:"Password updated. Other active sessions were signed out."});
  }
  if(path==="/api/auth/logout" && req.method==="POST") {
    const token=tokenFrom(req); if(token) await env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL").bind(new Date().toISOString(),await sha(token)).run();
    return response({authenticated:false},200,{"Set-Cookie":cookie("",0)});
  }
  if(path==="/api/auth/me" && req.method==="GET") {
    const user=await currentUser(req,env); return user?response({authenticated:true,user}):response({authenticated:false},401);
  }
  if(path==="/api/admin/users" && (req.method==="GET"||req.method==="POST")) {
    const actor=await currentUser(req,env); if(!actor) return response({error:"Authentication required"},401);
    if(actor.role!=="owner"&&actor.role!=="admin") return response({error:"Admin permission required"},403);
    if(req.method==="GET") {
      const users=await env.DB.prepare("SELECT u.id,u.email,u.display_name,m.role,u.is_active,u.created_at,u.last_login_at FROM users u JOIN organization_memberships m ON m.user_id=u.id WHERE m.organization_id=? ORDER BY u.created_at DESC").bind(actor.organization_id).all();
      return response({users:users.results});
    }
    const body=await req.json() as {email?:string;name?:string;password?:string;role?:string};
    const email=body.email?.trim().toLowerCase()||"", name=body.name?.trim()||"", password=body.password||"", role=body.role||"analyst";
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||name.length<2||password.length<14||password.length>256||!["admin","analyst","viewer"].includes(role)) return response({error:"Invalid user details"},400);
    if(actor.role!=="owner" && role==="admin") return response({error:"Only the organization owner can create administrators"},403);
    const membership={organization_id:actor.organization_id};
    const userId=id();
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,email,display_name,password_hash,role) VALUES(?,?,?,?,?)").bind(userId,email,name,await passwordHash(password),role),
        env.DB.prepare("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES(?,?,?)").bind(membership.organization_id,userId,role)
      ]);
      await log(env,actor.id,"admin_created_user");
      return response({created:true,user:{id:userId,email,name,role}},201);
    } catch { return response({error:"Could not create user; email may already exist"},409); }
  }
  const disableMatch=path.match(/^\/api\/admin\/users\/([0-9a-f-]+)$/);
  if(disableMatch && req.method==="DELETE") {
    const actor=await currentUser(req,env); if(!actor) return response({error:"Authentication required"},401);
    if(actor.role!=="owner"&&actor.role!=="admin") return response({error:"Admin permission required"},403);
    if(disableMatch[1]===actor.id) return response({error:"You cannot disable your own account"},400);
    const target=await env.DB.prepare("SELECT u.id,m.role FROM users u JOIN organization_memberships m ON m.user_id=u.id WHERE u.id=? AND m.organization_id=?").bind(disableMatch[1],actor.organization_id).first<{id:string;role:string}>();
    if(!target) return response({error:"User not found in your organization"},404);
    if(target.role==="owner") return response({error:"The organization owner cannot be disabled"},403);
    if(actor.role!=="owner" && target.role==="admin") return response({error:"Only the organization owner can disable administrators"},403);
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET is_active=0,updated_at=? WHERE id=?").bind(new Date().toISOString(),disableMatch[1]),
      env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL").bind(new Date().toISOString(),disableMatch[1])
    ]);
    await log(env,actor.id,"admin_disabled_user");
    return response({disabled:true});
  }
  return null;
}
