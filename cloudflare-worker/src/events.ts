import { currentUser } from "./auth";
import { evaluateSecurityEvent } from "./detections";

export type NormalizedSecurityEvent = {
  organizationId: string; collectorId: string | null; eventId: string; dedupKey: string;
  source: string; eventType: string; severity: "critical"|"high"|"medium"|"low"|"info"|"unknown";
  observedAt: string; receivedAt: string; host: string|null; sourceIp: string|null;
  destinationIp: string|null; username: string|null; message: string;
  normalized: Record<string,unknown>; raw: Record<string,unknown>;
};
type EventEnv = { DB:D1Database; EVENTS_QUEUE:Queue<NormalizedSecurityEvent>; AP_BRIDGE_KEY:string; ALLOWED_ORIGIN:string };
type CollectorRow = { id:string; org_id:string; is_paused:number };
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}});
const enc=new TextEncoder();
const b64=(b:Uint8Array)=>btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
async function hash(v:string){return b64(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(v))));}
function str(v:unknown,max=4000):string{return typeof v==="string"?v.trim().slice(0,max):v==null?"":String(v).slice(0,max);}
function scrub(v:unknown,depth=0):unknown{
 if(depth>8)return "[depth-limited]";
 if(Array.isArray(v))return v.slice(0,100).map(x=>scrub(x,depth+1));
 if(!v||typeof v!=="object")return typeof v==="string"?v.slice(0,4000):v;
 const out:Record<string,unknown>={};
 for(const [k,x] of Object.entries(v as Record<string,unknown>).slice(0,100)){
  if(/(password|secret|token|api.?key|authorization|cookie|private.?key|credential)/i.test(k))continue;
  out[k.slice(0,100)]=scrub(x,depth+1);
 }
 return out;
}
function severity(v:unknown):NormalizedSecurityEvent["severity"]{
 const s=str(v,24).toLowerCase();
 if(["critical","fatal","emergency"].includes(s))return "critical";
 if(["high","error","alert"].includes(s))return "high";
 if(["medium","warning","warn"].includes(s))return "medium";
 if(s==="low")return "low";
 if(["info","informational","notice"].includes(s))return "info";
 return "unknown";
}
async function normalize(org:string,collectorId:string|null,source:string,value:unknown):Promise<NormalizedSecurityEvent>{
 if(!value||typeof value!=="object"||Array.isArray(value))throw new Error("Each event must be a JSON object.");
 const outer=value as Record<string,unknown>;
 const nested=outer.payload&&typeof outer.payload==="object"&&!Array.isArray(outer.payload)?outer.payload as Record<string,unknown>:{};
 // Accept both flat collector events and the legacy { payload: {...} } envelope.
 const e={...outer,...nested};
 const raw=scrub(outer) as Record<string,unknown>;
 const eventData=e.eventData??e.event_data??e.EventData??{};
 const eventDetails=eventData&&typeof eventData==="object"?eventData as Record<string,unknown>:{};
 const wazuhData=eventDetails.data&&typeof eventDetails.data==="object"?eventDetails.data as Record<string,unknown>:{};
 const wazuhAgent=eventDetails.agent&&typeof eventDetails.agent==="object"?eventDetails.agent as Record<string,unknown>:{};
 const observedRaw=str(e.observedAt??outer.observedAt??e.timestamp??e.timeCreated??outer.timestamp??e["@timestamp"],80);
 const time=observedRaw?Date.parse(observedRaw):Date.now();
 if(!Number.isFinite(time))throw new Error("Event timestamp must be a valid date/time.");
 const observedAt=new Date(time).toISOString();
 const rule=(e.rule??eventDetails.rule)&&typeof (e.rule??eventDetails.rule)==="object"?(e.rule??eventDetails.rule) as Record<string,unknown>:{};
 const user=e.user&&typeof e.user==="object"?(e.user as Record<string,unknown>).name:e.user;
 const eventId=str(e.eventId??outer.eventId??e.id??e._id,180)||await hash(source+":"+observedAt+":"+JSON.stringify(raw));
 const dedupKey=await hash(org+":"+source+":"+eventId);
 const host=e.host&&typeof e.host==="object"?(e.host as Record<string,unknown>).name:e.host??wazuhAgent.name??wazuhAgent.id;
 const eventType=str(e.eventType??e.event_type??e.type??rule.description??e.category??"security_event",120);
 const eventNumber=str((eventData as Record<string,unknown>)?.EventID??(eventData as Record<string,unknown>)?.event_id??e.eventCode??e.event_code,12);
 const severityValue=e.severity??e.level??e.risk??(eventNumber==="1102"||eventNumber==="4697"?"high":eventNumber==="4625"?"medium":"info");
 const sev=severity(severityValue);
 const srcIp=str(e.sourceIp??e.srcIp??e.src_ip??e.source_ip??e.ipAddress??e.IpAddress??wazuhData.srcip??wazuhData.src_ip??wazuhData.source_ip,80)||null;
 const dstIp=str(e.destinationIp??e.dstIp??e.dest_ip??e.destination_ip??e.DestinationIp??wazuhData.dstip??wazuhData.dst_ip??wazuhData.destination_ip,80)||null;
 const username=str(e.username??e.TargetUserName??e.targetUserName??user??e.SubjectUserName??wazuhData.dstuser??wazuhData.srcuser??wazuhData.user,255)||null;
 const details=eventData&&typeof eventData==="object"?Object.entries(eventData as Record<string,unknown>).slice(0,24).map(([k,v])=>k+"="+str(v,180)).join(" "):"";
 const message=str(e.message??e.description??e.summary??[eventType,details].filter(Boolean).join(" | "),4000);
 const normalized:Record<string,unknown>={schemaVersion:"1.0",source,eventId,eventType,severity:sev,observedAt,host:str(host,255)||null,sourceIp:srcIp,destinationIp:dstIp,username,message,sourceIntegration:str(e.sourceIntegration??e.source_integration??source,160),dataOrigin:str(e.dataOrigin??e.data_origin??"UNVERIFIED",40),eventData:scrub(eventData)};
 return {organizationId:org,collectorId,eventId,dedupKey,source,eventType,severity:sev,observedAt,receivedAt:new Date().toISOString(),host:normalized.host as string|null,sourceIp:srcIp,destinationIp:dstIp,username,message,normalized,raw};
}
async function collector(req:Request,env:EventEnv,header="Authorization"):Promise<CollectorRow|null>{
 const h=req.headers.get(header)||"",token=header==="Authorization"?(h.startsWith("Bearer ")?h.slice(7):""):h;
 if(token.length<40||token.length>256)return null;
 return env.DB.prepare("SELECT id,org_id,is_paused FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL").bind(await hash(token)).first<CollectorRow>();
}
async function enqueue(env:EventEnv,org:string,cid:string|null,source:string,events:unknown[]){
 if(!env.EVENTS_QUEUE)throw new Error("Event queue binding is unavailable.");
 if(!Array.isArray(events)||events.length<1||events.length>100)throw new Error("Provide between 1 and 100 events.");
 const messages=await Promise.all(events.map(async body=>({body:await normalize(org,cid,source,body)})));
 await env.EVENTS_QUEUE.sendBatch(messages);
 return messages.length;
}
async function collectorIngest(req:Request,env:EventEnv){
 const c=await collector(req,env);if(!c)return json({error:"Invalid or revoked collector token."},401);
 if(c.is_paused)return json({error:"Collector is paused."},423);
 const raw=await req.text();if(raw.length>524288)return json({error:"Event batch exceeds 512 KB."},413);
 let body:Record<string,unknown>;try{body=JSON.parse(raw) as Record<string,unknown>;}catch{return json({error:"Invalid JSON."},400);}
 const source=str(body.integrationId??body.source,64).toLowerCase();
 if(!/^[a-z0-9_-]{2,64}$/.test(source))return json({error:"A valid integrationId/source is required."},400);
 try{const accepted=await enqueue(env,c.org_id,c.id,source,Array.isArray(body.events)?body.events:[]);
  await env.DB.prepare("UPDATE host_collectors SET last_seen_at=? WHERE id=? AND org_id=?").bind(new Date().toISOString(),c.id,c.org_id).run();
  return json({accepted,delivery:"queued",organizationScoped:true},202);
 }catch(e){return json({error:e instanceof Error?e.message:"Could not queue events."},400);}
}
async function webhookIngest(req:Request,env:EventEnv){
 const bridgeKey=req.headers.get("X-SentinelX-Bridge-Key")||req.headers.get("X-SentinelX-Key")||"";
 if(!env.AP_BRIDGE_KEY||bridgeKey!==env.AP_BRIDGE_KEY)return json({error:"Invalid bridge authentication."},401);
 const c=await collector(req,env,"X-SentinelX-Org-Key");if(!c)return json({error:"A valid organization collector token is required."},401);
 if(c.is_paused)return json({error:"Collector is paused."},423);
 const raw=await req.text();if(raw.length>524288)return json({error:"Event batch exceeds 512 KB."},413);
 let body:Record<string,unknown>;try{body=JSON.parse(raw) as Record<string,unknown>;}catch{return json({error:"Invalid JSON."},400);}
 const source=str(body.integrationId??body.source??"activepieces",64).toLowerCase();
 if(!/^[a-z0-9_-]{2,64}$/.test(source))return json({error:"A valid source is required."},400);
 const items=Array.isArray(body.events)?body.events:body.event?[body.event]:[];
 try{return json({accepted:await enqueue(env,c.org_id,c.id,source,items),delivery:"queued",organizationScoped:true},202);}
 catch(e){return json({error:e instanceof Error?e.message:"Could not queue events."},400);}
}
export async function handleEventRoute(req:Request,env:EventEnv,path:string):Promise<Response|null>{
 if(path==="/api/collector/events"&&req.method==="POST")return collectorIngest(req,env);
 if(path==="/api/events/ingest"&&req.method==="POST")return webhookIngest(req,env);
 if(path==="/api/events/summary"&&req.method==="GET"){
  const actor=await currentUser(req,env as Parameters<typeof currentUser>[1]);if(!actor)return json({error:"Authentication required."},401);
  const params=new URL(req.url).searchParams;
  const range=(params.get("range")||"24h").toLowerCase();
  const source=str(params.get("source"),64).toLowerCase();
  const config=range==="24h"?{format:"%Y-%m-%d %H:00",modifier:"-24 hours"}:range==="7d"?{format:"%Y-%m-%d",modifier:"-7 days"}:range==="30d"?{format:"%Y-%m-%d",modifier:"-30 days"}:null;
  if(!config)return json({error:"range must be 24h, 7d or 30d."},400);
  const rows=await env.DB.prepare("SELECT strftime(?,received_at) AS bucket,severity,COUNT(*) AS total FROM security_events WHERE org_id=? AND julianday(received_at)>=julianday('now',?) AND (?='' OR lower(source)=?) GROUP BY bucket,severity ORDER BY bucket")
   .bind(config.format,actor.organization_id,config.modifier,source,source).all<{bucket:string;severity:string;total:number}>();
  const buckets=new Map<string,Record<string,number>>();
  for(const row of rows.results){if(!row.bucket)continue;const item=buckets.get(row.bucket)||{critical:0,high:0,medium:0,low:0,info:0};const key=["critical","high","medium","low","info"].includes(row.severity)?row.severity:"info";item[key]+=Number(row.total||0);buckets.set(row.bucket,item);}
  const data=[...buckets.entries()].map(([label,counts])=>({label,...counts}));
  return json({data,range,source:source||"all"});
 }
 if(path==="/api/events"&&req.method==="GET"){
  const actor=await currentUser(req,env as Parameters<typeof currentUser>[1]);if(!actor)return json({error:"Authentication required."},401);
  const params=new URL(req.url).searchParams;
  const limit=Math.min(200,Math.max(1,Number(params.get("limit")||100)||100));
  const status=(params.get("status")||"active").toLowerCase();
  const source=str(params.get("source"),64).toLowerCase();
  if(!["active","archived","all"].includes(status))return json({error:"status must be active, archived or all."},400);
  const ageFilter=status==="active"?"julianday(received_at)>=julianday('now','-24 hours')":
   status==="archived"?"julianday(received_at)<julianday('now','-24 hours') AND julianday(received_at)>=julianday('now','-30 days')":
   "julianday(received_at)>=julianday('now','-30 days')";
  const rows=await env.DB.prepare("SELECT event_id,source,event_type,severity,observed_at,received_at,host,source_ip,destination_ip,username,message,normalized_json FROM security_events WHERE org_id=? AND ("+ageFilter+") AND (?='' OR lower(source)=?) ORDER BY received_at DESC LIMIT ?")
   .bind(actor.organization_id,source,source,limit).all<Record<string,unknown>>();
  return json({data:rows.results.map(r=>{let normalized:unknown={};try{normalized=JSON.parse(String(r.normalized_json));}catch{}return {...r,normalized};}),retention:{view:status,activeHours:24,totalDays:30,source:source||"all"}});
 }
 return null;
}
export async function consumeEventBatch(batch:MessageBatch<NormalizedSecurityEvent>,env:EventEnv):Promise<void>{
 for(const message of batch.messages){
  try{
   const e=message.body;if(!e?.organizationId||!e.dedupKey||!e.eventId||!e.source)throw new Error("Malformed queued event.");
   await env.DB.prepare("INSERT INTO security_events(id,org_id,event_id,dedup_key,source,collector_id,event_type,severity,observed_at,received_at,host,source_ip,destination_ip,username,message,normalized_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,dedup_key) DO NOTHING")
    .bind(crypto.randomUUID(),e.organizationId,e.eventId,e.dedupKey,e.source,e.collectorId,e.eventType,e.severity,e.observedAt,e.receivedAt,e.host,e.sourceIp,e.destinationIp,e.username,e.message,JSON.stringify(e.normalized),JSON.stringify(e.raw)).run();
   const row=await env.DB.prepare("SELECT id,detection_processed_at FROM security_events WHERE org_id=? AND dedup_key=?").bind(e.organizationId,e.dedupKey).first<{id:string;detection_processed_at:string|null}>();
   if(row&&!row.detection_processed_at){await evaluateSecurityEvent(env,row.id);await env.DB.prepare("UPDATE security_events SET detection_processed_at=? WHERE id=? AND org_id=? AND detection_processed_at IS NULL").bind(new Date().toISOString(),row.id,e.organizationId).run();}
   message.ack();
  }catch(error){
   console.error("SentinelX event pipeline delivery failed",{messageId:message.id,attempts:message.attempts,error:error instanceof Error?error.message:String(error)});
   message.retry({delaySeconds:Math.min(300,5*Math.max(1,message.attempts))});
  }
 }
}


/** Daily retention: keep events for 30 days; the API exposes the first 24h as active and the remainder as archived. */
export async function runScheduledRetention(env: EventEnv): Promise<void> {
 const results = await env.DB.batch([
  env.DB.prepare("DELETE FROM security_events WHERE julianday(received_at)<julianday('now','-30 days')"),
  env.DB.prepare("DELETE FROM security_incidents WHERE julianday(last_seen)<julianday('now','-30 days') AND NOT EXISTS (SELECT 1 FROM incident_events ie JOIN security_events e ON e.id=ie.event_row_id WHERE ie.org_id=security_incidents.org_id AND ie.incident_id=security_incidents.id AND julianday(e.received_at)>=julianday('now','-30 days'))"),
  env.DB.prepare("DELETE FROM security_incidents WHERE NOT EXISTS (SELECT 1 FROM incident_events ie JOIN security_events e ON e.id=ie.event_row_id WHERE ie.org_id=security_incidents.org_id AND ie.incident_id=security_incidents.id)")
 ]);
 console.log("SentinelX retention cleanup completed", { statements: results.length });
}
