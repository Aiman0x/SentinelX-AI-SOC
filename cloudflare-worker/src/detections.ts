import { currentUser } from "./auth";

type Severity = "critical"|"high"|"medium"|"low"|"info";
type Env = { DB:D1Database };
type Actor = { organization_id:string; role:string };
type EventRow = { id:string; org_id:string; event_id:string; source:string; event_type:string; severity:string; observed_at:string; host:string|null; source_ip:string|null; destination_ip:string|null; username:string|null; message:string; normalized_json:string; raw_json:string };
type Rule = { id:string; rule_key:string; title:string; description:string; severity:Severity; confidence:number; rule_type:string; sigma_yaml:string|null; definition_json:string; mitre_json:string };
const json=(v:unknown,s=200)=>new Response(JSON.stringify(v),{status:s,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}});
const uuid=()=>crypto.randomUUID();
const enc=new TextEncoder();
const hash=async(v:string)=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(v)))).map(x=>x.toString(16).padStart(2,"0")).join("");
const parse=(s:string)=>{try{return JSON.parse(s);}catch{return {};}};
const safe=(v:unknown)=>typeof v==="string"?v.slice(0,4000):v==null?"":String(v).slice(0,4000);
function severityRank(s:string){return ({info:1,low:2,medium:3,high:4,critical:5} as Record<string,number>)[s]||1;}
function worst(a:Severity,b:Severity):Severity{return severityRank(a)>=severityRank(b)?a:b;}
function flatten(obj:unknown,prefix="",out:Record<string,unknown>={}):Record<string,unknown>{
 if(!obj||typeof obj!=="object"||Array.isArray(obj))return out;
 for(const [k,v] of Object.entries(obj as Record<string,unknown>)){const key=prefix?prefix+"."+k:k;out[key]=v;if(v&&typeof v==="object"&&!Array.isArray(v))flatten(v,key,out);}
 return out;
}
function matchValue(actual:unknown,expected:unknown):boolean{
 if(Array.isArray(expected))return expected.some(x=>matchValue(actual,x));
 if(expected&&typeof expected==="object"){const ops=expected as Record<string,unknown>;return Object.entries(ops).every(([op,val])=>{const a=String(actual??"").toLowerCase(),b=String(val??"").toLowerCase();if(op==="contains")return a.includes(b);if(op==="startswith")return a.startsWith(b);if(op==="endswith")return a.endsWith(b);if(op==="re")try{return new RegExp(String(val),"i").test(a);}catch{return false;}if(op==="all")return Array.isArray(val)&&val.every(x=>matchValue(actual,x));return false;});}
 return String(actual??"").toLowerCase()===String(expected??"").toLowerCase();
}
function sigmaSelection(yaml:string,event:Record<string,unknown>):boolean{
 const lines=yaml.split(/\r?\n/);let inDetection=false,section="",selection:Record<string,Record<string,unknown>>={},condition="";
 for(const raw of lines){const line=raw.replace(/\s+#.*$/,"");if(!line.trim())continue;
  if(/^detection:\s*$/.test(line)){inDetection=true;continue;}if(!inDetection)continue;
  const top=line.match(/^  ([A-Za-z0-9_* -]+):\s*(.*)$/);
  if(top){section=top[1].trim();if(section==="condition"){condition=top[2].trim().replace(/^['"]|['"]$/g,"");continue;}selection[section]=selection[section]||{};continue;}
  const field=line.match(/^    ([A-Za-z0-9_.| -]+):\s*(.*)$/);
  if(field&&section){const rawField=field[1],parts=rawField.split("|"),modifier=parts.length>1?parts[parts.length-1]:((rawField.match(/_(contains|startswith|endswith)$/)||[])[1]||""),baseField=parts.length>1?parts.slice(0,-1).join("|"):modifier?rawField.slice(0,rawField.lastIndexOf("_")):rawField,key=baseField.toLowerCase();const value=parseScalar(field[2]);selection[section][key]=modifier?{[modifier]:value}:value;continue;}
  const list=line.match(/^      -\s*(.*)$/);if(list&&section){const keys=Object.keys(selection[section]);const key=keys[keys.length-1];if(key)selection[section][key]=[...(Array.isArray(selection[section][key])?selection[section][key] as unknown[]:[selection[section][key]]),parseScalar(list[1])];}
 }
 const flat=flatten(event);const normalized:Record<string,unknown>={};for(const [k,v] of Object.entries(flat))normalized[k.toLowerCase()]=v;
 const names=Object.keys(selection);if(!names.length||!condition)return false;
 const evalSel=(n:string)=>Object.entries(selection[n]).every(([k,v])=>matchValue(normalized[k]??normalized[k.split(".").pop()||k],v));
 const cond=condition.toLowerCase().replace(/[()]/g," ").replace(/\s+/g," ").trim();
 if(cond==="all of them")return names.every(evalSel);
 if(cond==="1 of them")return names.some(evalSel);
 const wildcard=cond.match(/^(all|1) of ([a-z0-9_*]+)$/);if(wildcard){const matching=names.filter(n=>wildcard[2].endsWith("*")?n.startsWith(wildcard[2].slice(0,-1)):n===wildcard[2]);return wildcard[1]==="all"?matching.length>0&&matching.every(evalSel):matching.some(evalSel);}
 const clauses=cond.split(/\s+(and|or)\s+/);let value=evalSel(clauses[0]);for(let i=1;i<clauses.length;i+=2){const next=evalSel(clauses[i+1]);value=clauses[i]==="and"?(value&&next):(value||next);}return value;
}
function parseScalar(v:string):unknown{const s=v.trim();if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'")))return s.slice(1,-1);if(s==="true")return true;if(s==="false")return false;if(s==="null")return null;if(s.startsWith("[")&&s.endsWith("]"))return s.slice(1,-1).split(",").map(x=>parseScalar(x));return s;}
function mitreFor(e:EventRow):Array<{id:string;name:string}>{
 const t=(e.event_type+" "+e.message).toLowerCase();const out:Array<{id:string;name:string}>=[];
 if(/failed.?login|authentication.?failure|4625/.test(t))out.push({id:"T1110",name:"Brute Force"});
 if(/successful.?login|4624|remote.?logon/.test(t))out.push({id:"T1078",name:"Valid Accounts"});
 if(/powershell|script.?interpreter|wscript|cscript/.test(t))out.push({id:"T1059",name:"Command and Scripting Interpreter"});
 if(/scheduled.?task|registry.?run|persistence|service.?install/.test(t))out.push({id:"T1053",name:"Scheduled Task/Job"});
 if(/dns|outbound|network.?connection|beacon/.test(t))out.push({id:"T1071",name:"Application Layer Protocol"});
 return out;
}
function sigmaMitre(yaml:string):Array<{id:string;name:string}>{
 const ids=[...new Set((yaml.match(/attack\.t\d{4}(?:\.\d{3})?/gi)||[]).map(x=>x.split(".")[1].toUpperCase()))];
 const names:Record<string,string>={T1110:"Brute Force",T1078:"Valid Accounts",T1059:"Command and Scripting Interpreter",T1053:"Scheduled Task/Job",T1021:"Remote Services",T1071:"Application Layer Protocol",T1547:"Boot or Logon Autostart Execution"};
 return ids.slice(0,20).map(id=>({id,name:names[id]||"MITRE ATT&CK technique"}));
}
function incidentFingerprint(org:string,rule:string,e:EventRow){return [org,rule,(e.host||"").toLowerCase(),(e.username||"").toLowerCase(),(e.source_ip||"").toLowerCase()].join("|");}
async function builtinMatches(db:D1Database,e:EventRow):Promise<Array<{key:string;title:string;description:string;severity:Severity;confidence:number;mitre:Array<{id:string;name:string}>}>>{
 const ev=parse(e.normalized_json) as Record<string,unknown>;const text=(e.event_type+" "+e.message).toLowerCase();const out=[];
 const count=async(sql:string,...args:unknown[])=>{const r=await db.prepare(sql).bind(...args).first<{n:number}>();return Number(r?.n||0);};
 const hasIdentity=Boolean(e.username||e.source_ip);
 const failures=hasIdentity?await count("SELECT COUNT(*) n FROM security_events WHERE org_id=? AND source_ip IS ? AND username IS ? AND observed_at>=datetime(?,'-10 minutes') AND observed_at<=? AND (lower(event_type) LIKE '%fail%' OR event_type='windows_failed_login')",e.org_id,e.source_ip,e.username,e.observed_at,e.observed_at):0;
 if(failures>=5&&(/fail|4625/.test(text)))out.push({key:"SX-AUTH-001",title:"Repeated Authentication Failures",description:\`\${failures} failed authentication events for the same user/source within 10 minutes.\`,severity:"high" as Severity,confidence:88,mitre:[{id:"T1110",name:"Brute Force"}]});
 const success=hasIdentity?await count("SELECT COUNT(*) n FROM security_events WHERE org_id=? AND source_ip IS ? AND username IS ? AND observed_at>=datetime(?,'-10 minutes') AND observed_at<=? AND (lower(event_type) LIKE '%success%' OR event_type='windows_successful_login')",e.org_id,e.source_ip,e.username,e.observed_at,e.observed_at):0;
 if(failures>=3&&success>0&&(/success|4624/.test(text)))out.push({key:"SX-AUTH-002",title:"Failed Logons Followed by Success",description:\`\${failures} failed logons followed by a successful logon for the same account/source within 10 minutes.\`,severity:"critical",confidence:94,mitre:[{id:"T1110",name:"Brute Force"},{id:"T1078",name:"Valid Accounts"}]});
 if(/powershell|encodedcommand|wscript|cscript|mshta/.test(text))out.push({key:"SX-END-001",title:"Suspicious Script Interpreter Activity",description:"Script interpreter activity matched a high-risk execution pattern.",severity:"high",confidence:78,mitre:[{id:"T1059",name:"Command and Scripting Interpreter"}]});
 if(/runonce|currentversion\\run|scheduled.?task|service.?install/.test(text))out.push({key:"SX-END-002",title:"Persistence-Related Configuration Change",description:"Event indicates a persistence-related configuration change.",severity:"high",confidence:80,mitre:[{id:"T1053",name:"Scheduled Task/Job"}]});
 if(/remote.?service|psexec|admin\$|remote.?logon/.test(text))out.push({key:"SX-END-003",title:"Unexpected Remote Service Logon",description:"Event contains remote service or administrative-share activity.",severity:"high",confidence:75,mitre:[{id:"T1021",name:"Remote Services"}]});
 if(/periodic|beacon|repeated outbound|regular outbound/.test(text))out.push({key:"SX-NET-001",title:"Potential Periodic Outbound Communication",description:"Network event matched a beacon-like or repeated outbound communication pattern.",severity:"medium",confidence:65,mitre:[{id:"T1071",name:"Application Layer Protocol"}]});
 void ev;return out;
}
async function addFinding(env:Env,e:EventRow,rule:{key:string;title:string;description:string;severity:Severity;confidence:number;mitre:Array<{id:string;name:string}>},sourceRuleType="builtin"){
 const key=incidentFingerprint(e.org_id,rule.key,e);const incidentId=uuid();const now=e.observed_at;
 await env.DB.prepare("INSERT INTO security_incidents(id,org_id,incident_key,title,description,severity,confidence,first_seen,last_seen,event_count,host,username,source_ip,mitre_json,detection_json) VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?, ?,?) ON CONFLICT(org_id,incident_key) DO UPDATE SET severity=CASE WHEN excluded.severity='critical' OR (excluded.severity='high' AND security_incidents.severity NOT IN ('critical')) OR (excluded.severity='medium' AND security_incidents.severity IN ('low','info')) THEN excluded.severity ELSE security_incidents.severity END,confidence=MAX(security_incidents.confidence,excluded.confidence),last_seen=MAX(security_incidents.last_seen,excluded.last_seen),mitre_json=excluded.mitre_json,updated_at=CURRENT_TIMESTAMP")
 .bind(incidentId,e.org_id,key,rule.title,rule.description,rule.severity,rule.confidence,now,now,e.host,e.username,e.source_ip,JSON.stringify(rule.mitre),JSON.stringify({ruleKey:rule.key,ruleType:sourceRuleType})).run();
 const incident=await env.DB.prepare("SELECT id FROM security_incidents WHERE org_id=? AND incident_key=?").bind(e.org_id,key).first<{id:string}>();if(!incident)return;
 await env.DB.prepare("INSERT OR IGNORE INTO incident_events(org_id,incident_id,event_row_id,rule_key) VALUES(?,?,?,?)").bind(e.org_id,incident.id,e.id,rule.key).run();
 const payload=JSON.stringify({eventId:e.event_id,source:e.source,eventType:e.event_type,severity:e.severity,observedAt:e.observed_at,host:e.host,username:e.username,sourceIp:e.source_ip,destinationIp:e.destination_ip,message:e.message,normalized:parse(e.normalized_json),raw:parse(e.raw_json),rule:{key:rule.key,title:rule.title,description:rule.description},mitre:rule.mitre});
 const digest=await hash(payload);const evidenceId=uuid();
 await env.DB.prepare("INSERT OR IGNORE INTO evidence_records(id,org_id,incident_id,event_row_id,rule_key,evidence_type,captured_at,sha256,payload_json) VALUES(?,?,?,?,?,'event_snapshot',?,?,?)").bind(evidenceId,e.org_id,incident.id,e.id,rule.key,new Date().toISOString(),digest,payload).run();
 const totals=await env.DB.prepare("SELECT COUNT(*) AS event_count,COUNT(DISTINCT e.source) AS source_count FROM incident_events ie JOIN security_events e ON e.id=ie.event_row_id WHERE ie.org_id=? AND ie.incident_id=?").bind(e.org_id,incident.id).first<{event_count:number;source_count:number}>();const evidenceTotal=await env.DB.prepare("SELECT COUNT(*) AS n FROM evidence_records WHERE org_id=? AND incident_id=?").bind(e.org_id,incident.id).first<{n:number}>();const confidence=Math.min(99,rule.confidence+Math.min(8,Math.max(0,Number(totals?.event_count||1)-1)*2)+(Number(totals?.source_count||1)>1?5:0));await env.DB.prepare("UPDATE security_incidents SET event_count=?,evidence_count=?,confidence=MAX(confidence,?),updated_at=CURRENT_TIMESTAMP WHERE org_id=? AND id=?").bind(Number(totals?.event_count||1),Number(evidenceTotal?.n||0),confidence,e.org_id,incident.id).run();
}
export async function evaluateSecurityEvent(env:Env,eventId:string):Promise<void>{
 const e=await env.DB.prepare("SELECT id,org_id,event_id,source,event_type,severity,observed_at,host,source_ip,destination_ip,username,message,normalized_json,raw_json FROM security_events WHERE id=?").bind(eventId).first<EventRow>();if(!e)return;
 const rules=await builtinMatches(env.DB,e);for(const r of rules)await addFinding(env,e,r);
 const custom=await env.DB.prepare("SELECT rule_key,title,description,severity,confidence,rule_type,sigma_yaml,definition_json,mitre_json FROM detection_rules WHERE org_id=? AND enabled=1").bind(e.org_id).all<Rule>();
 const flat={...parse(e.normalized_json),source:e.source,event_type:e.event_type,host:e.host,source_ip:e.source_ip,destination_ip:e.destination_ip,username:e.username,message:e.message,severity:e.severity};
 for(const r of custom.results){let matched=false;if(r.rule_type==="sigma"&&r.sigma_yaml)matched=sigmaSelection(r.sigma_yaml,flat);else{const def=parse(r.definition_json) as Record<string,unknown>;matched=Object.entries(def).every(([k,v])=>matchValue((flat as Record<string,unknown>)[k],v));}
  if(matched){const mitre=parse(r.mitre_json);await addFinding(env,e,{key:r.rule_key,title:r.title,description:r.description||"Custom detection rule matched.",severity:r.severity,confidence:r.confidence,mitre:Array.isArray(mitre)?mitre:[]},r.rule_type);}
 }
}
export async function handleDetectionRoute(req:Request,env:Env,path:string):Promise<Response|null>{
 if(!path.startsWith("/api/detections/")&&!path.startsWith("/api/incidents")&&!path.startsWith("/api/evidence"))return null;
 const actor=await currentUser(req,env as Parameters<typeof currentUser>[1]) as Actor|null;if(!actor)return json({error:"Authentication required."},401);
 const org=actor.organization_id;
 if(path==="/api/detections/rules"&&req.method==="GET"){const r=await env.DB.prepare("SELECT rule_key,title,description,enabled,severity,confidence,rule_type,sigma_yaml,mitre_json,created_at,updated_at FROM detection_rules WHERE org_id=? ORDER BY rule_key").bind(org).all();return json({builtinRules:[{ruleKey:"SX-AUTH-001",title:"Repeated Authentication Failures",severity:"high",mitre:["T1110"]},{ruleKey:"SX-AUTH-002",title:"Failed Logons Followed by Success",severity:"critical",mitre:["T1110","T1078"]},{ruleKey:"SX-END-001",title:"Suspicious Script Interpreter Activity",severity:"high",mitre:["T1059"]},{ruleKey:"SX-END-002",title:"Persistence-Related Configuration Change",severity:"high",mitre:["T1053"]},{ruleKey:"SX-END-003",title:"Unexpected Remote Service Logon",severity:"high",mitre:["T1021"]},{ruleKey:"SX-NET-001",title:"Potential Periodic Outbound Communication",severity:"medium",mitre:["T1071"]}],customRules:r.results});}
 if(path==="/api/detections/rules"&&req.method==="POST"){
  if(!["owner","admin"].includes(actor.role))return json({error:"Admin permission required."},403);
  const body=await req.json() as Record<string,unknown>;const key=safe(body.ruleKey).trim(),title=safe(body.title).trim(),yaml=typeof body.sigmaYaml==="string"?body.sigmaYaml:"";
  if(!/^[A-Za-z0-9_.-]{3,100}$/.test(key)||!title||title.length>200)return json({error:"Valid ruleKey and title are required."},400);
  const isSigma=body.ruleType==="sigma";if(isSigma&&(!yaml||yaml.length>20000||!/^detection:\s*$/m.test(yaml)||!/^\s*condition:/m.test(yaml)))return json({error:"Sigma rule must include detection and condition sections and be <=20KB."},400);
  const severity=(["critical","high","medium","low","info"].includes(String(body.severity))?String(body.severity):"medium") as Severity;const confidence=Math.max(1,Math.min(100,Number(body.confidence)||70));
  const mitre=Array.isArray(body.mitre)?body.mitre.filter(x=>x&&typeof x==="object"&&/^T\d{4}(?:\.\d{3})?$/.test(String((x as Record<string,unknown>).id||""))).slice(0,20):(isSigma?sigmaMitre(yaml):[]);
  await env.DB.prepare("INSERT INTO detection_rules(id,org_id,rule_key,title,description,enabled,severity,confidence,rule_type,sigma_yaml,definition_json,mitre_json) VALUES(?,?,?,?,?,1,?,?,?,?,?,?) ON CONFLICT(org_id,rule_key) DO UPDATE SET title=excluded.title,description=excluded.description,enabled=1,severity=excluded.severity,confidence=excluded.confidence,rule_type=excluded.rule_type,sigma_yaml=excluded.sigma_yaml,definition_json=excluded.definition_json,mitre_json=excluded.mitre_json,updated_at=CURRENT_TIMESTAMP").bind(uuid(),org,key,title,safe(body.description),severity,confidence,isSigma?"sigma":"builtin",isSigma?yaml:null,JSON.stringify(body.definition||{}),JSON.stringify(mitre)).run();
  return json({saved:true,ruleKey:key,ruleType:isSigma?"sigma":"builtin"},201);
 }
 if(path==="/api/detections/rules"&&req.method==="DELETE"){
  if(!["owner","admin"].includes(actor.role))return json({error:"Admin permission required."},403);const key=new URL(req.url).searchParams.get("ruleKey");if(!key)return json({error:"ruleKey required."},400);await env.DB.prepare("UPDATE detection_rules SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE org_id=? AND rule_key=?").bind(org,key).run();return json({disabled:true});
 }
 if((path==="/api/incidents"||path==="/api/detections/findings")&&req.method==="GET"){const limit=Math.min(200,Math.max(1,Number(new URL(req.url).searchParams.get("limit")||100)||100));const r=await env.DB.prepare("SELECT id,incident_key,title,description,severity,confidence,status,first_seen,last_seen,event_count,host,username,source_ip,mitre_json,evidence_count,created_at,updated_at FROM security_incidents WHERE org_id=? ORDER BY updated_at DESC LIMIT ?").bind(org,limit).all();return json({data:r.results});}
 const incidentMatch=path.match(/^\/api\/incidents\/([0-9a-f-]+)$/i);if(incidentMatch&&req.method==="GET"){const r=await env.DB.prepare("SELECT * FROM security_incidents WHERE org_id=? AND id=?").bind(org,incidentMatch[1]).first();if(!r)return json({error:"Incident not found."},404);const events=await env.DB.prepare("SELECT e.*,ie.rule_key FROM incident_events ie JOIN security_events e ON e.id=ie.event_row_id WHERE ie.org_id=? AND ie.incident_id=? ORDER BY e.observed_at").bind(org,incidentMatch[1]).all();const evidence=await env.DB.prepare("SELECT id,rule_key,evidence_type,captured_at,sha256,payload_json FROM evidence_records WHERE org_id=? AND incident_id=? ORDER BY captured_at").bind(org,incidentMatch[1]).all();return json({incident:r,events:events.results,evidence:evidence.results});}
 if(path==="/api/evidence/verify"&&req.method==="GET"){const id=new URL(req.url).searchParams.get("id");if(!id)return json({error:"Evidence id required."},400);const r=await env.DB.prepare("SELECT sha256,payload_json FROM evidence_records WHERE org_id=? AND id=?").bind(org,id).first<{sha256:string;payload_json:string}>();if(!r)return json({error:"Evidence not found."},404);const actual=await hash(r.payload_json);return json({verified:actual===r.sha256,expectedHash:r.sha256,actualHash:actual});}
 if(path==="/api/evidence"&&req.method==="GET"){const incidentId=new URL(req.url).searchParams.get("incidentId");if(!incidentId)return json({error:"incidentId required."},400);const r=await env.DB.prepare("SELECT id,incident_id,event_row_id,rule_key,evidence_type,captured_at,sha256,payload_json FROM evidence_records WHERE org_id=? AND incident_id=? ORDER BY captured_at").bind(org,incidentId).all();return json({data:r.results});}
 return json({error:"Not found."},404);
}
