import { currentUser } from "./auth";

type Env = { DB: D1Database; INTEGRATION_CONFIGS: KVNamespace; CONFIG_ENCRYPTION_KEY: string; ALLOWED_ORIGIN: string };
type Actor = { id: string; role: string; organization_id: string };
const json = (body: unknown, status=200) => new Response(JSON.stringify(body), {status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}});
const enc = new TextEncoder();
const b64 = (v:Uint8Array) => btoa(String.fromCharCode(...v)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64 = (v:string) => Uint8Array.from(atob(v.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-v.length%4)%4)),c=>c.charCodeAt(0));
const keyFor = (a:Actor) => a.organization_id+":"+a.id+":mcp";
async function seal(value:unknown,secret:string,aad:string) {
  if(!/^[0-9a-f]{64}$/i.test(secret)) throw new Error("Secure storage is not configured.");
  const key=await crypto.subtle.importKey("raw",Uint8Array.from(secret.match(/.{2}/g)!,x=>parseInt(x,16)),{name:"AES-GCM"},false,["encrypt"]);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:enc.encode(aad)},key,enc.encode(JSON.stringify(value)));
  return JSON.stringify({iv:b64(iv),data:b64(new Uint8Array(data))});
}
async function unseal(raw:string,secret:string,aad:string):Promise<Record<string,string>> {
  if(!/^[0-9a-f]{64}$/i.test(secret)) throw new Error("Secure storage is not configured.");
  const key=await crypto.subtle.importKey("raw",Uint8Array.from(secret.match(/.{2}/g)!,x=>parseInt(x,16)),{name:"AES-GCM"},false,["decrypt"]);
  const envelope=JSON.parse(raw) as {iv:string;data:string};
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(envelope.iv),additionalData:enc.encode(aad)},key,unb64(envelope.data));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string,string>;
}
async function readConfig(env:Env,actor:Actor) {
  const key=keyFor(actor),raw=await env.INTEGRATION_CONFIGS.get(key);
  if(!raw) throw new Error("Connect an MCP server first.");
  return unseal(raw,env.CONFIG_ENCRYPTION_KEY,key);
}
async function audited(env:Env,actor:Actor,event:string,details:Record<string,unknown>,run:()=>Promise<unknown>) {
  const id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(id,actor.organization_id,actor.id,"Human Analyst",event,"mcp",JSON.stringify(details),"Started").run();
  try {
    const data=await run();
    await env.DB.prepare("UPDATE audit_logs SET outcome=?,details=? WHERE id=? AND org_id=?")
      .bind("Success",JSON.stringify({...details,result:"returned"}),id,actor.organization_id).run();
    return data;
  } catch(error) {
    const message=error instanceof Error?error.message.slice(0,240):"MCP request failed";
    await env.DB.prepare("UPDATE audit_logs SET outcome=?,details=? WHERE id=? AND org_id=?")
      .bind("Failure",JSON.stringify({...details,error:message}),id,actor.organization_id).run();
    throw error;
  }
}
async function dispatch(env:Env,actor:Actor,config:Record<string,string>,operation:"test"|"query",input:Record<string,unknown>={}) {
  const bridge=await env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND bridge_enabled=1 AND revoked_at IS NULL AND last_seen_at>=? ORDER BY last_seen_at DESC LIMIT 1")
    .bind(actor.organization_id,new Date(Date.now()-90_000).toISOString()).first<{id:string}>();
  if(!bridge) throw new Error("No online SentinelX Local Bridge. Start your enrolled bridge on a machine that can reach the MCP server.");
  const taskId=crypto.randomUUID(),created=new Date(),expires=new Date(created.getTime()+30_000).toISOString();
  await env.DB.prepare("INSERT INTO bridge_tasks(id,org_id,collector_id,actor_id,connector_id,request_json,status,created_at,expires_at) VALUES(?,?,?,?,? ,?,'queued',?,?)")
    .bind(taskId,actor.organization_id,bridge.id,actor.id,"mcp",await seal({operation,config,input},env.CONFIG_ENCRYPTION_KEY,"bridge-task:"+taskId),created.toISOString(),expires).run();
  const deadline=Date.now()+25_000;
  while(Date.now()<deadline) {
    const row=await env.DB.prepare("SELECT status,result_json FROM bridge_tasks WHERE id=? AND org_id=? AND collector_id=?")
      .bind(taskId,actor.organization_id,bridge.id).first<{status:string;result_json:string|null}>();
    if(row?.status==="completed"||row?.status==="failed") {
      if(!row.result_json) throw new Error("Local Bridge returned an empty MCP result.");
      const result=await unseal(row.result_json,env.CONFIG_ENCRYPTION_KEY,"bridge-result:"+taskId) as unknown as {ok:boolean;message:string;data?:unknown};
      if(!result.ok) throw new Error(result.message||"MCP request failed.");
      return result.data??{message:result.message};
    }
    if(row?.status==="expired") throw new Error("MCP task expired before execution.");
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  await env.DB.prepare("UPDATE bridge_tasks SET status='expired' WHERE id=? AND status IN ('queued','claimed')").bind(taskId).run();
  throw new Error("Local Bridge did not respond within 25 seconds.");
}
function validEndpoint(value:string) {
  try {
    const u=new URL(value);
    return ["http:","https:"].includes(u.protocol)&&!!u.hostname&&!u.username&&!u.password&&!u.search&&!u.hash&&
      !["169.254.169.254","metadata.google.internal","metadata.azure.internal"].includes(u.hostname.toLowerCase());
  } catch { return false; }
}
export async function handleMcpRoute(req:Request,env:Env,path:string):Promise<Response|null> {
  if(!path.startsWith("/api/mcp/")) return null;
  const origin=req.headers.get("Origin")||"";
  if(origin&&!env.ALLOWED_ORIGIN.split(",").map(x=>x.trim()).includes(origin)) return json({error:"Origin not allowed"},403);
  const actor=await currentUser(req,env as Parameters<typeof currentUser>[1]);
  if(!actor) return json({error:"Authentication required"},401);
  if(actor.role!=="owner"&&actor.role!=="admin"&&actor.role!=="analyst") return json({error:"Insufficient permission"},403);
  if(req.method!=="POST") return json({error:"Method not allowed"},405);
  let body:Record<string,unknown>;
  try { const value=await req.json(); if(!value||typeof value!=="object"||Array.isArray(value)) throw new Error(); body=value as Record<string,unknown>; }
  catch { return json({error:"Invalid JSON body"},400); }
  try {
    if(path==="/api/mcp/connect") {
      const serverUrl=typeof body.serverUrl==="string"?body.serverUrl.trim():"";
      const bearerToken=typeof body.bearerToken==="string"?body.bearerToken.trim():"";
      const label=typeof body.label==="string"?body.label.trim().slice(0,80):"MCP server";
      if(!validEndpoint(serverUrl)) return json({error:"Enter a valid HTTP/HTTPS MCP endpoint without embedded credentials, query or fragment."},400);
      if(bearerToken.length>2048) return json({error:"Bearer token is too long."},400);
      const key=keyFor(actor);
      const old=await env.INTEGRATION_CONFIGS.get(key);
      const previous=old?await unseal(old,env.CONFIG_ENCRYPTION_KEY,key):{};
      await env.INTEGRATION_CONFIGS.put(key,await seal({...previous,serverUrl,label,bearerToken:bearerToken||previous.bearerToken||""},env.CONFIG_ENCRYPTION_KEY,key));
      return json({saved:true,label,serverUrl,bearerTokenSaved:!!bearerToken,secretsHidden:true});
    }
    const config=await readConfig(env,actor);
    if(path==="/api/mcp/test"||path==="/api/mcp/tools") {
      const data=await dispatch(env,actor,config,path.endsWith("/test")?"test":"query",{action:"list"});
      return json({ok:true,data});
    }
    if(path==="/api/mcp/call") {
      const toolName=typeof body.toolName==="string"?body.toolName.trim():"";
      if(!toolName||toolName.length>128) return json({error:"Choose a valid MCP tool name."},400);
      let args:unknown={};
      if(body.arguments!==undefined) args=body.arguments;
      if(!args||typeof args!=="object"||Array.isArray(args)) return json({error:"Tool arguments must be a JSON object."},400);
      const data=await dispatch(env,actor,config,"query",{action:"call",toolName,arguments:args});
      return json({data});
    }
    return json({error:"Unknown MCP route"},404);
  } catch(e) { return json({error:e instanceof Error?e.message:"MCP request failed."},400); }
}
