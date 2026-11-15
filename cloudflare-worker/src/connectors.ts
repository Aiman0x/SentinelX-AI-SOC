import { currentUser } from "./auth";

type Actor = { id: string; role: string; organization_id: string };
type FieldSchema = { key: string; label: string; type: "text" | "password" | "url"; required?: boolean; placeholder: string; help?: string };
type AdapterContext = { request: Request; env: ConnectorEnv; actor: Actor; values: Record<string, string> };
type ConnectorEnv = { DB: D1Database; INTEGRATION_CONFIGS: KVNamespace; CONFIG_ENCRYPTION_KEY: string; ALLOWED_ORIGIN: string; AP_READ_SECURITY_INTEGRATIONS_URL?: string; AP_BRIDGE_KEY?: string };
type AdapterResult = { ok: boolean; message: string; checkedAt: string; details?: unknown };
interface ToolAdapter {
  id: string; name: string; category: string; description: string;
  schema: { version: "1.0"; fields: FieldSchema[]; query: { supported: boolean; description: string; fields?: FieldSchema[] } };
  connect(context: AdapterContext, values: Record<string, string>): Promise<{ saved: boolean; configuredKeys: string[] }>;
  test(context: AdapterContext): Promise<AdapterResult>;
  query(context: AdapterContext, input: Record<string, unknown>): Promise<unknown>;
  disconnect(context: AdapterContext): Promise<void>;
}
const now = () => new Date().toISOString();
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
const enc = new TextEncoder();
const b64 = (v: Uint8Array) => btoa(String.fromCharCode(...v)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const unb64 = (v: string) => Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4-v.length%4)%4)), c => c.charCodeAt(0));
function storageKey(actor: Actor, id: string) { return actor.organization_id + ":" + actor.id + ":" + id; }
async function audit(context: AdapterContext, event: string, connectorId: string, outcome: string) {
  // Security-relevant connector operations must never report success when their
  // audit record could not be persisted. Let the caller return an explicit 503.
  await context.env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),context.actor.organization_id,context.actor.id,"Human Analyst",event,connectorId,"Connector operation: "+connectorId,outcome).run();
}

async function cryptKey(secret: string, usage: KeyUsage[]) {
  if (!/^[0-9a-f]{64}$/i.test(secret)) throw new Error("Secure integration encryption key is not configured.");
  return crypto.subtle.importKey("raw", Uint8Array.from(secret.match(/.{2}/g)!, x => parseInt(x,16)), {name:"AES-GCM"}, false, usage);
}
async function seal(value: unknown, secret: string, aad: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await cryptKey(secret, ["encrypt"]);
  const data = await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:enc.encode(aad)},key,enc.encode(JSON.stringify(value)));
  return JSON.stringify({iv:b64(iv),data:b64(new Uint8Array(data))});
}
async function unseal(value: string, secret: string, aad: string): Promise<Record<string,string>> {
  const env = JSON.parse(value) as {iv:string;data:string};
  const key = await cryptKey(secret, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(env.iv),additionalData:enc.encode(aad)},key,unb64(env.data));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string,string>;
}
function publicHttps(value: string) {
  try {
    const u = new URL(value);
    const h = u.hostname.toLowerCase();
    if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return false;
    if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return false;
    if (/^(?:0|10|127|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}$/.test(h)) return false;
    if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) return false;
    return true;
  } catch { return false; }
}
async function fetchJson(url: string, init: RequestInit = {}, timeoutMs = 10000): Promise<{response:Response;data:any}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {...init, signal:controller.signal, redirect:"manual"});
    const raw = await response.text();
    let data: any = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = { message: "Provider returned a non-JSON response." }; }
    return {response,data};
  } finally { clearTimeout(timeout); }
}
async function disconnectStored(context: AdapterContext, id: string) {
  const key = storageKey(context.actor, id);
  await context.env.INTEGRATION_CONFIGS.delete(key);
  await context.env.INTEGRATION_CONFIGS.delete(key + ":health");
  // Host-side non-secret settings are shared with enrolled collectors. Remove
  // them only when no other user in this organization still has this connector.
  const orgKey = context.actor.organization_id + ":" + id;
  const listed = await context.env.INTEGRATION_CONFIGS.list({ prefix: context.actor.organization_id + ":", limit: 1000 });
  const anotherUserConfigured = listed.keys.some(item =>
    item.name !== orgKey && item.name.endsWith(":" + id) && !item.name.endsWith(":health")
  );
  if (listed.list_complete && !anotherUserConfigured) {
    await context.env.INTEGRATION_CONFIGS.delete(orgKey);
    await context.env.INTEGRATION_CONFIGS.delete(orgKey + ":health");
  }
}
async function saved(context: AdapterContext, id: string) {
  const key = storageKey(context.actor,id);
  const raw = await context.env.INTEGRATION_CONFIGS.get(key);
  if (!raw) throw new Error("Connect this tool with your own credentials first.");
  return unseal(raw,context.env.CONFIG_ENCRYPTION_KEY,key);
}
function health(context: AdapterContext,id:string,result:AdapterResult) {
  return context.env.INTEGRATION_CONFIGS.put(storageKey(context.actor,id)+":health",JSON.stringify(result));
}
function validateIndicator(input: Record<string,unknown>) {
  const type = String(input.type || "").toLowerCase();
  const value = typeof input.indicator === "string" ? input.indicator.trim() : "";
  if (!value || value.length > 2048) throw new Error("Provide an indicator (IP, domain, URL, or file hash).");
  if (type === "ip") {
    if (!/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}|[0-9a-fA-F:]{3,39})$/.test(value)) throw new Error("Enter a valid IP address.");
  } else if (type === "domain") {
    if (!/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(value)) throw new Error("Enter a valid domain.");
  } else if (type === "hash") {
    if (!/^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(value)) throw new Error("Enter a valid MD5, SHA-1 or SHA-256 hash.");
  } else if (type === "url") {
    let u: URL; try { u = new URL(value); } catch { throw new Error("Enter a valid URL."); }
    if (!["http:","https:"].includes(u.protocol) || u.username || u.password) throw new Error("Only HTTP/HTTPS URLs without embedded credentials are supported.");
  } else throw new Error("Choose indicator type: ip, domain, url or hash.");
  return {type,value};
}
const field = (key:string,label:string,placeholder:string,type:FieldSchema["type"]="text",required=false,help?:string):FieldSchema => ({key,label,placeholder,type,required,help});
function threatAdapter(id:"virustotal"|"abuseipdb"|"urlscan"):ToolAdapter {
  const meta = id==="virustotal" ? {name:"VirusTotal",description:"Look up IPs, domains, URLs and file hashes using your VirusTotal API key.",fields:[field("apiKey","VirusTotal API key","Paste your own API key","password",true)]}
    : id==="abuseipdb" ? {name:"AbuseIPDB",description:"Check IP reputation and abuse confidence using your AbuseIPDB API key.",fields:[field("apiKey","AbuseIPDB API key","Paste your own API key","password",true)]}
    : {name:"URLScan",description:"Search historical URL and domain scans using your URLScan API key.",fields:[field("apiKey","URLScan API key","Paste your own API key","password",true)]};
  return {
    id,name:meta.name,category:"Threat Intelligence",description:meta.description,
    schema:{version:"1.0",fields:meta.fields,query:{supported:true,description:id==="abuseipdb"?"Look up a public IPv4/IPv6 address.":"Look up a public IP, domain, URL or file hash.",fields:[field("type","Indicator type","ip / domain / url / hash","text",true),field("indicator","Indicator value","IP, domain, URL or hash","text",true)]}},
    async connect(context,values) {
      if(Object.keys(values).some(k=>k!=="apiKey")) throw new Error("Only an API key is accepted for this connector.");
      if(!values.apiKey || values.apiKey.length<8 || values.apiKey.length>512) throw new Error("Enter a valid API key.");
      const key=storageKey(context.actor,id), old=await context.env.INTEGRATION_CONFIGS.get(key);
      const previous=old?await unseal(old,context.env.CONFIG_ENCRYPTION_KEY,key):{};
      await context.env.INTEGRATION_CONFIGS.put(key,await seal({...previous,...values},context.env.CONFIG_ENCRYPTION_KEY,key));
      return {saved:true,configuredKeys:["apiKey"]};
    },
    async disconnect(context) { await disconnectStored(context, id); },
    async test(context) {
      const at=now();
      try {
        const values=await saved(context,id);
        let response:Response;
        if(id==="virustotal") response=(await fetchJson("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",{headers:{"x-apikey":values.apiKey,Accept:"application/json"}})).response;
        else if(id==="abuseipdb") response=(await fetchJson("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90",{headers:{Key:values.apiKey,Accept:"application/json"}})).response;
        else response=(await fetchJson("https://urlscan.io/api/v1/quotas/",{headers:{"api-key":values.apiKey,Accept:"application/json"}})).response;
        if(!response.ok) throw new Error(meta.name+" rejected the key or request (HTTP "+response.status+").");
        const ok={ok:true,message:meta.name+" API key accepted; read-only API check succeeded.",checkedAt:at};
        await health(context,id,ok); return ok;
      } catch(e) {
        const fail={ok:false,message:e instanceof Error?e.message:meta.name+" test failed.",checkedAt:at};
        await health(context,id,fail); return fail;
      }
    },
    async query(context,input) {
      const values=await saved(context,id); const {type,value}=validateIndicator(input);
      if(id==="abuseipdb" && type!=="ip") throw new Error("AbuseIPDB check supports IP addresses only.");
      if(id==="virustotal") {
        const path=type==="ip"?"ip_addresses/"+encodeURIComponent(value):type==="domain"?"domains/"+encodeURIComponent(value):type==="hash"?"files/"+encodeURIComponent(value):"urls/"+b64(enc.encode(value));
        const r=await fetchJson("https://www.virustotal.com/api/v3/"+path,{headers:{"x-apikey":values.apiKey,Accept:"application/json"}});
        if(!r.response.ok) throw new Error("VirusTotal lookup failed (HTTP "+r.response.status+").");
        return r.data;
      }
      if(id==="abuseipdb") {
        const r=await fetchJson("https://api.abuseipdb.com/api/v2/check?ipAddress="+encodeURIComponent(value)+"&maxAgeInDays=90",{headers:{Key:values.apiKey,Accept:"application/json"}});
        if(!r.response.ok) throw new Error("AbuseIPDB lookup failed (HTTP "+r.response.status+").");
        return r.data;
      }
      const query=type==="domain"?"page.domain:"+value:type==="ip"?"ip:"+value:type==="url"?'page.url:"'+value.replace(/["\\]/g,"")+'"':"hash:"+value;
      const r=await fetchJson("https://urlscan.io/api/v1/search/?q="+encodeURIComponent(query)+"&size=10",{headers:{"api-key":values.apiKey,Accept:"application/json"}});
      if(!r.response.ok) throw new Error("URLScan search failed (HTTP "+r.response.status+").");
      return r.data;
    }
  };
}
function hostAdapter(id:"wazuh"|"sysmon"|"windows_security"|"suricata"|"zeek"|"clamav"|"yara",name:string,description:string):ToolAdapter {
  const labels:Record<string,string>={wazuh:"Wazuh Manager + Indexer alert stream",sysmon:"Microsoft-Windows-Sysmon/Operational",windows_security:"Windows Security Event Log",suricata:"/var/log/suricata/eve.json",zeek:"/opt/zeek/logs/current",clamav:"clamd / clamscan scan results",yara:"YARA rule scan results"};
  return {
    id,name,category:id==="wazuh"?"SIEM":id==="sysmon"||id==="windows_security"?"Endpoint":id==="clamav"||id==="yara"?"Malware":"Network",description,
    schema:{version:"1.0",fields:id==="windows_security"||id==="wazuh"?[]:[field("sensor","Sensor / host name","endpoint-01"),field("source","Telemetry source path or channel",labels[id])],query:{supported:true,description:"Retrieve recent tenant-scoped endpoint or sensor events.",fields:[field("limit","Maximum records (1–100)","50"),field("eventType","Exact event type (optional)","windows_event_4624"),field("host","Exact host name (optional)","DESKTOP-01"),field("username","Account name (optional)","SYSTEM"),field("eventId","Exact source event ID (optional)","wazuh-archive:001:12345"),field("contains","Search message or raw event text (optional)","service install"),field("sinceMinutes","Look-back window in minutes","1440"),field("startTime","Absolute start time (ISO 8601, optional)","2026-11-15T20:00:00Z"),field("endTime","Absolute end time (ISO 8601, optional)","2026-11-15T20:20:00Z")]}},
    async connect(context,values) {
      if(Object.keys(values).some(k=>!["sensor","source"].includes(k))) throw new Error("Unsupported configuration field.");
      const key=storageKey(context.actor,id),old=await context.env.INTEGRATION_CONFIGS.get(key);
      const prev=old?await unseal(old,context.env.CONFIG_ENCRYPTION_KEY,key):{};
      const merged={...prev,...values};
      await context.env.INTEGRATION_CONFIGS.put(key,await seal(merged,context.env.CONFIG_ENCRYPTION_KEY,key));
      // Host-side settings are non-secret metadata; mirror only these to the organization collector scope.
      const orgKey=context.actor.organization_id+":"+id,orgOld=await context.env.INTEGRATION_CONFIGS.get(orgKey);
      const orgPrev=orgOld?await unseal(orgOld,context.env.CONFIG_ENCRYPTION_KEY,orgKey):{};
      await context.env.INTEGRATION_CONFIGS.put(orgKey,await seal({...orgPrev,...values},context.env.CONFIG_ENCRYPTION_KEY,orgKey));
      return {saved:true,configuredKeys:Object.keys(merged)};
    },
    async disconnect(context) { await disconnectStored(context, id); },
    async test(context) {
      if(id==="wazuh") {
        const raw=await context.env.INTEGRATION_CONFIGS.get(context.actor.organization_id+":wazuh:health");
        if(!raw) {
          const missing={ok:false,message:"No Wazuh poller heartbeat received yet. Enroll the Linux Wazuh VM and start its poller.",checkedAt:now()};
          await health(context,id,missing); return missing;
        }
        try {
          const h=JSON.parse(raw); const age=Date.now()-Date.parse(h.checkedAt||"");
          const metrics=h.metrics||{}; const summary="Wazuh poller healthy — "+Number(metrics.agentCount||0)+" agents, "+Number(metrics.alertsMatched||0)+" alerts matched in the last poll."; const result={ok:h.ok===true&&age>=0&&age<600000,message:age>=600000?"Wazuh poller heartbeat is stale.":h.ok===true?summary:h.message||"Wazuh poller reported a problem.",checkedAt:now(),details:{collectorStatus:h.status,observedAt:h.checkedAt,metrics}};
          await health(context,id,result); return result;
        } catch {
          const invalid={ok:false,message:"Wazuh poller health report is invalid.",checkedAt:now()};
          await health(context,id,invalid); return invalid;
        }
      }
      if(id==="windows_security") {
        const latest=await context.env.DB.prepare("SELECT observed_at,event_type,host FROM security_events WHERE org_id=? AND source='windows_security' ORDER BY observed_at DESC LIMIT 1").bind(context.actor.organization_id).first<{observed_at:string;event_type:string;host:string|null}>();
        const age=latest?Date.now()-Date.parse(latest.observed_at):Number.POSITIVE_INFINITY;
        const result={ok:!!latest&&age>=0&&age<10*60_000,message:!latest?"No Windows Security events received yet. Start the enrolled Windows collector.":age>=10*60_000?"Windows Security telemetry is stale.":"Windows Security events are arriving from the enrolled host.",checkedAt:now(),details:latest?{lastEventAt:latest.observed_at,eventType:latest.event_type,host:latest.host}:undefined};
        await health(context,id,result); return result;
      }
      const raw=await context.env.INTEGRATION_CONFIGS.get(context.actor.organization_id+":"+id+":health");
      if(!raw) {
        const missing={ok:false,message:"No recent host collector health report. Install/enroll the collector on the sensor first.",checkedAt:now()};
        await health(context,id,missing); return missing;
      }
      try {
        const h=JSON.parse(raw); const age=Date.now()-Date.parse(h.checkedAt||"");
        const result={ok:h.ok===true&&h.status==="healthy"&&age>=0&&age<600000,message:age>=600000?"Collector health report is stale.":h.message||"Collector health report received.",checkedAt:now(),details:{collectorStatus:h.status,observedAt:h.checkedAt}};
        await health(context,id,result); return result;
      } catch {
        const invalid={ok:false,message:"Collector health report is invalid.",checkedAt:now()};
        await health(context,id,invalid); return invalid;
      }
    },
    async query(context,input) {
      const limit=Math.min(100,Math.max(1,Number(input.limit)||50));
      const source=id==="sysmon"?"sysmon":id==="windows_security"?"windows_security":id;
      const eventType=typeof input.eventType==="string"?input.eventType.trim().slice(0,120):"";
      const host=typeof input.host==="string"?input.host.trim().slice(0,255):"";
      const username=typeof input.username==="string"?input.username.trim().slice(0,255):"";
      const eventId=typeof input.eventId==="string"?input.eventId.trim().slice(0,180):"";
      const contains=typeof input.contains==="string"?input.contains.trim().slice(0,160):"";
      const sinceMinutes=Math.min(10080,Math.max(1,Number(input.sinceMinutes)||1440));
      const startCandidate=typeof input.startTime==="string"?input.startTime.trim():"";
      const endCandidate=typeof input.endTime==="string"?input.endTime.trim():"";
      const startTime=startCandidate&&Number.isFinite(Date.parse(startCandidate))?new Date(startCandidate).toISOString():"";
      const endTime=endCandidate&&Number.isFinite(Date.parse(endCandidate))?new Date(endCandidate).toISOString():"";
      const like="%"+contains.toLowerCase()+"%";
      const rows=await context.env.DB.prepare(
        "SELECT event_id,source,event_type,severity,observed_at,received_at,host,source_ip,destination_ip,username,message,normalized_json,raw_json FROM security_events WHERE org_id=? AND source=? AND ((?<>'' AND observed_at>=?) OR (?='' AND observed_at>=strftime('%Y-%m-%dT%H:%M:%fZ','now',?))) AND (?='' OR observed_at<=?) AND (?='' OR event_type=?) AND (?='' OR lower(COALESCE(host,''))=lower(?)) AND (?='' OR lower(COALESCE(username,''))=lower(?)) AND (?='' OR event_id=?) AND (?='' OR lower(COALESCE(message,'')) LIKE ? OR lower(event_type) LIKE ? OR lower(COALESCE(raw_json,'')) LIKE ?) ORDER BY observed_at DESC LIMIT ?"
      ).bind(context.actor.organization_id,source,startTime,startTime,startTime,"-"+sinceMinutes+" minutes",endTime,endTime,eventType,eventType,host,host,username,username,eventId,eventId,contains,like,like,like,limit).all<Record<string,unknown>>();
      const data=rows.results.map(row=>{
        let event:unknown={},raw:unknown={};try{event=JSON.parse(String(row.normalized_json));}catch{}try{raw=JSON.parse(String(row.raw_json));}catch{}
        const find=(names:string[]):unknown=>{const wanted=new Set(names.map(x=>x.toLowerCase().replace(/[^a-z0-9]/g,"")));const visit=(node:unknown):unknown=>{if(!node||typeof node!=="object")return undefined;for(const [key,value] of Object.entries(node as Record<string,unknown>))if(wanted.has(key.toLowerCase().replace(/[^a-z0-9]/g,""))&&value!==null&&value!==undefined&&String(value)!=="")return value;for(const value of Object.values(node as Record<string,unknown>)){const found=visit(value);if(found!==undefined)return found;}return undefined;};return visit(event)??visit(raw);};
        const code=String(find(["eventID","eventCode"])??String(row.event_type||"").match(/(?:4624|5140|5145|5379|4798|4625|4672|4697|4720|4728|4732)/)?.[0]??row.event_type??"");
        return {time:row.observed_at,type:code,user:row.username??null,host:row.host??null,logonType:find(["logonType","logon_type"])??null,process:find(["processName","process_name","image","processPath"])??null,ip:row.source_ip??find(["ipAddress","sourceIp","srcIp"])??null,share:find(["shareName","share_name","relativeTargetName"])??null,eventId:row.event_id,source:row.source,severity:row.severity};
      });
      const aggregate=(key:string)=>{const counts:Record<string,number>={};for(const row of data){const value=String((row as Record<string,unknown>)[key]??"unknown");counts[value]=(counts[value]||0)+1;}return counts;};
      return {data,count:data.length,source,window:{start:startTime||null,end:endTime||null,sinceMinutes:startTime?null:sinceMinutes},aggregates:{byType:aggregate("type"),byLogonType:aggregate("logonType"),byProcess:aggregate("process"),byUser:aggregate("user")},filters:{eventType:eventType||null,host:host||null,username:username||null,eventId:eventId||null,contains:contains||null}};
    }
  };
}
const activepieces: ToolAdapter = {
  id:"activepieces",name:"ActivePieces",category:"Orchestration",description:"Connect the SentinelX workflow bridge for event ingestion, triage and automation.",
  schema:{version:"1.0",fields:[],query:{supported:false,description:"Workflow execution remains controlled by SentinelX gateway routes."}},
  async connect() { return {saved:true,configuredKeys:[]}; },
  async disconnect(context) { await disconnectStored(context, this.id); },
  async test(context) {
    const at=now();
    try {
      if(!context.env.AP_READ_SECURITY_INTEGRATIONS_URL||!context.env.AP_BRIDGE_KEY) throw new Error("ActivePieces read webhook or bridge key is not configured on the SentinelX gateway.");
      const r=await fetchJson(context.env.AP_READ_SECURITY_INTEGRATIONS_URL,{headers:{Accept:"application/json","X-SentinelX-Bridge-Key":context.env.AP_BRIDGE_KEY}});
      if(!r.response.ok) throw new Error("ActivePieces webhook returned HTTP "+r.response.status+".");
      const result={ok:true,message:"ActivePieces bridge webhook is reachable.",checkedAt:at};
      await health(context,this.id,result); return result;
    } catch(e) {
      const result={ok:false,message:e instanceof Error?e.message:"ActivePieces health check failed.",checkedAt:at};
      await health(context,this.id,result); return result;
    }
  },
  async query() { throw new Error("Use SentinelX workflow and SOC data routes for ActivePieces-backed data."); }
};
const cloudflareResponse: ToolAdapter = {
  id:"cloudflare_response",name:"Cloudflare Response",category:"Response",description:"Approval-gated Cloudflare zone IP blocking. This connector is never exposed to the read-only AI tool catalog.",
  schema:{version:"1.0",fields:[
    field("apiToken","Cloudflare API token","Token with Zone Firewall Services Edit permission","password",true,"Use a dedicated least-privilege token limited to the intended zone."),
    field("zoneId","Cloudflare Zone ID","Your zone ID","text",true,"Only this zone is eligible for IP block actions.")
  ],query:{supported:false,description:"Action-only integration. Never callable by the read-only agent."}},
  async connect(context,values) {
    if(Object.keys(values).some(k=>!["apiToken","zoneId"].includes(k))) throw new Error("Unsupported Cloudflare Response field.");
    if(!values.apiToken || values.apiToken.length<20 || values.apiToken.length>512) throw new Error("Provide a Cloudflare API token.");
    if(!/^[a-f0-9]{32}$/i.test(values.zoneId||"")) throw new Error("Zone ID must be 32 hexadecimal characters.");
    const key=storageKey(context.actor,this.id),old=await context.env.INTEGRATION_CONFIGS.get(key);
    const prev=old?await unseal(old,context.env.CONFIG_ENCRYPTION_KEY,key):{};
    await context.env.INTEGRATION_CONFIGS.put(key,await seal({...prev,...values},context.env.CONFIG_ENCRYPTION_KEY,key));
    return {saved:true,configuredKeys:["apiToken","zoneId"]};
  },
  async disconnect(context) { await disconnectStored(context, this.id); },
  async test(context) {
    const at=now();
    try {
      const v=await saved(context,this.id);
      if(!/^[a-f0-9]{32}$/i.test(v.zoneId||"")) throw new Error("Zone ID is invalid.");
      const r=await fetchJson("https://api.cloudflare.com/client/v4/zones/"+encodeURIComponent(v.zoneId),{headers:{Authorization:"Bearer "+v.apiToken,Accept:"application/json"}});
      if(!r.response.ok || r.data?.success!==true) throw new Error("Cloudflare token cannot read the configured zone (HTTP "+r.response.status+"). Check zone scope and token permissions.");
      const result={ok:true,message:"Cloudflare zone is reachable. Actual block permission is checked when an approved action is executed.",checkedAt:at,details:{zoneId:v.zoneId,zoneName:r.data?.result?.name||null}};
      await health(context,this.id,result); return result;
    } catch(e) {
      const result={ok:false,message:e instanceof Error?e.message:"Cloudflare response connection failed.",checkedAt:at};
      await health(context,this.id,result); return result;
    }
  },
  async query() { throw new Error("Action-only integration; it cannot be queried by the AI agent."); }
};

const adapters: ToolAdapter[] = [
  cloudflareResponse,
  activepieces,
  hostAdapter("wazuh","Wazuh","Wazuh Manager and Indexer alerts streamed securely from your Linux Wazuh VM. No public Wazuh API or Indexer endpoint is required."),
  hostAdapter("windows_security","Windows Security Logs","Windows authentication, process creation, account, group and audit events delivered by the enrolled endpoint collector."),
  hostAdapter("sysmon","Windows Sysmon","Windows process, network, registry, DNS and image events delivered by the enrolled endpoint collector."),
  hostAdapter("suricata","Suricata","Network IDS/IPS alerts and protocol metadata from eve.json via a network sensor collector."),
  hostAdapter("zeek","Zeek","Network connection, DNS, HTTP and TLS metadata via a network sensor collector."),
  hostAdapter("clamav","ClamAV","Malware scan results and daemon health delivered by the enrolled host collector."),
  hostAdapter("yara","YARA","YARA rule-match and file-scan results delivered by the enrolled host collector."),
  threatAdapter("virustotal"),threatAdapter("abuseipdb"),threatAdapter("urlscan")
];

export async function getAgentToolCatalog(request: Request, env: ConnectorEnv) {
  const actor = await currentUser(request, env as Parameters<typeof currentUser>[1]);
  if (!actor) throw new Error("Authentication required");
  const tools = [];
  for (const adapter of adapters) {
    if (!adapter.schema.query.supported) continue;
    const key = storageKey(actor, adapter.id);
    const collectorBacked = adapter.id === "windows_security" || adapter.id === "sysmon" || adapter.id === "wazuh"
      ? Boolean(await env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND revoked_at IS NULL AND is_paused=0 AND (?=0 OR platform='linux') LIMIT 1").bind(actor.organization_id,adapter.id==="wazuh"?1:0).first())
      : false;
    const configured = collectorBacked || Boolean(await env.INTEGRATION_CONFIGS.get(key));
    if (!configured) continue;
    const healthRaw = await env.INTEGRATION_CONFIGS.get(key + ":health");
    let healthState: "verified" | "unverified" | "failed" = "unverified";
    if (healthRaw) {
      try { const h = JSON.parse(healthRaw); healthState = h.ok === true ? "verified" : "failed"; } catch { healthState = "failed"; }
    }
    tools.push({ id: adapter.id, name: adapter.name, description: adapter.description, query: adapter.schema.query, health: healthState, access: "read_only" });
  }
  return { actor, tools };
}

export async function runAgentTool(request: Request, env: ConnectorEnv, actor: Actor, connectorId: string, input: Record<string, unknown>) {
  const adapter = adapters.find(x => x.id === connectorId && x.schema.query.supported);
  if (!adapter) throw new Error("Tool is not in the read-only allowlist.");
  const key = storageKey(actor, connectorId);
  const collectorBacked = connectorId === "windows_security" || connectorId === "sysmon" || connectorId === "wazuh"
    ? Boolean(await env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND revoked_at IS NULL AND is_paused=0 AND (?=0 OR platform='linux') LIMIT 1").bind(actor.organization_id,connectorId==="wazuh"?1:0).first())
    : false;
  if (!collectorBacked && !(await env.INTEGRATION_CONFIGS.get(key))) throw new Error("This tool is not connected for your account or organization.");
  const auditId = crypto.randomUUID();
  // Fail closed: do not call a connector unless the audit start record is persisted.
  await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(auditId, actor.organization_id, actor.id, "AI Agent", "agent_tool_call", connectorId,
      JSON.stringify({ connectorId, inputFields: Object.keys(input).slice(0, 12), mode: "read_only" }), "Started").run();
  try {
    const data = await adapter.query({ request, env, actor, values: {} }, input);
    await env.DB.prepare("UPDATE audit_logs SET outcome=?,details=? WHERE id=? AND org_id=?")
      .bind("Success", JSON.stringify({ connectorId, inputFields: Object.keys(input).slice(0, 12), mode: "read_only", result: "returned" }), auditId, actor.organization_id).run();
    return data;
  } catch (error) {
    const safeMessage = error instanceof Error ? error.message.slice(0, 240) : "Tool query failed";
    await env.DB.prepare("UPDATE audit_logs SET outcome=?,details=? WHERE id=? AND org_id=?")
      .bind("Failure", JSON.stringify({ connectorId, inputFields: Object.keys(input).slice(0, 12), mode: "read_only", error: safeMessage }), auditId, actor.organization_id).run();
    throw error;
  }
}

export async function handleConnectorRoute(request:Request,env:ConnectorEnv,path:string):Promise<Response|null> {
  if(!path.startsWith("/api/integrations") && !path.startsWith("/api/response/")) return null;
  const actor=await currentUser(request,env as Parameters<typeof currentUser>[1]);
  if(!actor) return json({error:"Authentication required"},401);
  const executeMatch=path.match(/^\/api\/response\/execute\/([A-Za-z0-9_-]+)$/);
  if(executeMatch && request.method==="POST") {
    if(actor.role!=="owner" && actor.role!=="admin") return json({error:"Owner/admin approval required."},403);
    const approvalId=decodeURIComponent(executeMatch[1]);
    const approval=await env.DB.prepare("SELECT id,approval_id,org_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,action_binding_hash,requested_by_actor_id,approved_by_actor_id,status,expires_at,execution_status,execution_attempt_id FROM approvals WHERE org_id=? AND approval_id=? LIMIT 1")
      .bind(actor.organization_id,approvalId).first<any>();
    if(!approval) return json({error:"Approval not found in this workspace."},404);
    if(approval.status!=="Approved" || !approval.approved_by_actor_id) return json({error:"Action must be approved before execution."},409);
    if(approval.requested_by_actor_id && approval.requested_by_actor_id===approval.approved_by_actor_id) return json({error:"Four-eyes control failed: requester and approver must differ."},403);
    if(approval.approved_by_actor_id!==actor.id) return json({error:"Only the authenticated approver may execute this approved request."},403);
    if(approval.expires_at && Date.parse(approval.expires_at)<=Date.now()) return json({error:"Approval expired. Request and approve a new action."},410);
    if(approval.execution_status!=="Not Executed" || approval.execution_attempt_id) return json({error:"Action is already executed or an execution attempt exists; inspect audit records before retrying."},409);
    if(approval.action_type!=="block_ip") return json({error:"No production executor is enabled for this action type."},501);
    const target=String(approval.target_asset||"").trim();
    // Rebuild the exact canonical payload used when the approval was requested.
    // Refuse execution if any action-defining field changed after approval.
    const actionBinding=JSON.stringify({
      org: actor.organization_id,
      caseId: approval.case_id ?? null,
      actionType: approval.action_type,
      targetAsset: approval.target_asset ?? "",
      proposed: approval.proposed_action,
      reason: approval.reason_evidence,
      risk: approval.risk_level,
    });
    const expectedBindingHash=btoa(String.fromCharCode(...new Uint8Array(
      await crypto.subtle.digest("SHA-256",new TextEncoder().encode(actionBinding))
    )));
    if(typeof approval.action_binding_hash!=="string" || approval.action_binding_hash!==expectedBindingHash) {
      return json({error:"Approval integrity check failed: action details no longer match the approved request. Cancel this approval and create a new one."},409);
    }
    const validV4=/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(target);
    const validV6=/^[0-9a-fA-F:]{3,39}$/.test(target) && target.includes(":");
    if(!validV4&&!validV6) return json({error:"The approved target_asset must be a single IPv4 or IPv6 address."},400);
    const configKey=storageKey(actor,"cloudflare_response");
    const raw=await env.INTEGRATION_CONFIGS.get(configKey);
    if(!raw) return json({error:"Connect and test your own Cloudflare Response integration first."},400);
    const values=await unseal(raw,env.CONFIG_ENCRYPTION_KEY,configKey);
    const attempt=crypto.randomUUID();
    const claim=await env.DB.prepare("UPDATE approvals SET execution_attempt_id=?,execution_status='Execution Started',lifecycle_state='EXECUTING',execution_mode='REAL ACTION - Cloudflare IP Access Rule' WHERE org_id=? AND approval_id=? AND status='Approved' AND execution_status='Not Executed' AND execution_attempt_id IS NULL")
      .bind(attempt,actor.organization_id,approvalId).run();
    if((claim.meta?.changes??0)!==1) return json({error:"Could not claim this approval; reload its current state."},409);
    try {
      // Persist the start audit before any external side effect. If it fails, no
      // provider request is made and the catch block marks the claimed attempt failed.
      await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
        .bind(attempt,actor.organization_id,actor.id,"Human Approver","response_execution_started",approvalId,JSON.stringify({actionType:"block_ip",target,provider:"cloudflare",zoneId:values.zoneId,approvalId}),"Started").run();
      if(!/^[a-f0-9]{32}$/i.test(values.zoneId||"")) throw new Error("Configured Cloudflare Zone ID is invalid.");
      const response=await fetchJson("https://api.cloudflare.com/client/v4/zones/"+encodeURIComponent(values.zoneId)+"/firewall/access_rules/rules",{
        method:"POST",headers:{Authorization:"Bearer "+values.apiToken,Accept:"application/json","Content-Type":"application/json"},
        body:JSON.stringify({mode:"block",configuration:{target:validV4?"ip":"ip6",value:target},notes:"SentinelX approved action "+approvalId+"; review audit trail before removal."})
      });
      if(!response.response.ok || response.data?.success!==true) throw new Error("Cloudflare rejected the block request (HTTP "+response.response.status+"). Check token permission and zone.");
      const providerId=String(response.data?.result?.id||"");
      if(!providerId) throw new Error("Cloudflare created no rule ID; inspect the provider before retrying.");
      const verify=await fetchJson("https://api.cloudflare.com/client/v4/zones/"+encodeURIComponent(values.zoneId)+"/firewall/access_rules/rules/"+encodeURIComponent(providerId),{headers:{Authorization:"Bearer "+values.apiToken,Accept:"application/json"}});
      const verified=verify.response.ok && verify.data?.success===true && String(verify.data?.result?.configuration?.value||"")===target;
      await env.DB.prepare("UPDATE approvals SET execution_status=?,lifecycle_state=?,execution_result=?,verification_result=?,audit_reference=? WHERE org_id=? AND approval_id=? AND execution_attempt_id=?")
        .bind(verified?"Executed":"Executed - verification inconclusive",verified?"EXECUTED":"VERIFY_INCONCLUSIVE",JSON.stringify({provider:"cloudflare",providerRuleId:providerId,target,verified}),verified?"Cloudflare rule read-back matched the approved IP.":"Rule was created but read-back verification was inconclusive.",attempt,actor.organization_id,approvalId,attempt).run();
      await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
        .bind(crypto.randomUUID(),actor.organization_id,actor.id,"Human Approver","response_execution_completed",approvalId,JSON.stringify({actionType:"block_ip",target,provider:"cloudflare",providerRuleId:providerId,verified}),verified?"Success":"Warning").run();
      return json({executed:true,verified,approvalId,actionType:"block_ip",target,provider:"cloudflare",providerRuleId:providerId,verification:verified?"read_back_confirmed":"inconclusive",note:"This is a real network access-control change. Confirm service impact and removal procedure."},verified?200:202);
    } catch(e) {
      const message=e instanceof Error?e.message:"Provider execution failed.";
      await env.DB.prepare("UPDATE approvals SET execution_status='Execution Failed - inspect provider',lifecycle_state='EXECUTION_FAILED',execution_result=?,verification_result='Not verified' WHERE org_id=? AND approval_id=? AND execution_attempt_id=?")
        .bind(message.slice(0,500),actor.organization_id,approvalId,attempt).run();
      await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
        .bind(crypto.randomUUID(),actor.organization_id,actor.id,"Human Approver","response_execution_failed",approvalId,message.slice(0,500),"Failure").run().catch(()=>undefined);
      return json({error:message,approvalId,executionStatus:"Execution Failed - inspect provider before retrying"},502);
    }
  }

  if(request.method==="GET" && path==="/api/integrations") {
    const data=[];
    for(const adapter of adapters) {
      const key=storageKey(actor,adapter.id);
      const raw=await env.INTEGRATION_CONFIGS.get(key);
      const collectorBacked=(adapter.id==="windows_security"||adapter.id==="sysmon"||adapter.id==="wazuh")
        ? Boolean(await env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND revoked_at IS NULL AND is_paused=0 AND (?=0 OR platform='linux') LIMIT 1").bind(actor.organization_id,adapter.id==="wazuh"?1:0).first())
        : false;
      const healthRaw=await env.INTEGRATION_CONFIGS.get(key+":health");
      const health=healthRaw?JSON.parse(healthRaw):null;
      let configuredKeys:string[]=[];
      if(raw) { try { configuredKeys=Object.keys(await unseal(raw,env.CONFIG_ENCRYPTION_KEY,key)); } catch {} }
      const capabilities = ["schema", "connect", "test", "disconnect", ...(adapter.schema.query.supported ? ["query"] : [])];
      data.push({id:adapter.id,name:adapter.name,category:adapter.category,purpose:adapter.description,description:adapter.description,schema:adapter.schema,fields:adapter.schema.fields,capabilities,configured:!!raw||collectorBacked,configuredKeys,verified:health?.ok===true,state:health?.ok===true?"connected":raw||collectorBacked?"disconnected":"not_configured",lastHealthCheck:health?.checkedAt||null,health:health?{ok:health.ok===true,message:health.message,checkedAt:health.checkedAt}:null});
    }
    return json({data,registryVersion:"1.0"});
  }
  if(request.method==="GET" && path==="/api/integrations/capabilities") {
    return json({registryVersion:"1.1",data:adapters.map(adapter=>({
      id:adapter.id,name:adapter.name,category:adapter.category,
      capabilities:["schema","connect","test","disconnect",...(adapter.schema.query.supported?["query"]:[])],
      schema:adapter.schema
    }))});
  }
  const match=path.match(/^\/api\/integrations\/([a-z0-9_-]+)\/(schema|connect|test|query|disconnect)$/);
  if(!match) return json({error:"Unknown integration route"},404);
  const adapter=adapters.find(x=>x.id===match[1]);
  if(!adapter) return json({error:"Unknown connector"},404);
  if((match[2]==="connect" || match[2]==="disconnect") && actor.role==="viewer") return json({error:"Viewer role cannot manage connector configuration."},403);
  if(match[2]==="schema"&&request.method==="GET") return json({id:adapter.id,schema:adapter.schema,capabilities:["schema","connect","test","disconnect",...(adapter.schema.query.supported?["query"]:[])]});
  if(match[2]==="disconnect"&&request.method==="DELETE") {
    try { await adapter.disconnect({request,env,actor,values:{}}); }
    catch(e) { return json({error:e instanceof Error?e.message:"Could not disconnect connector."},503); }
    try { await audit({request,env,actor,values:{}},"integration_disconnected",adapter.id,"Success"); }
    catch { return json({error:"Connector was disconnected, but its security audit could not be written. Refresh the integration status before retrying.",disconnected:true},503); }
    return json({disconnected:true,connectionState:"not_configured"});
  }
  if(match[2]==="connect"&&request.method==="POST") {
    let body:any; try { body=await request.json(); } catch { return json({error:"Invalid JSON body"},400); }
    if(!body?.values||typeof body.values!=="object"||Array.isArray(body.values)) return json({error:"values object required"},400);
    const allowed=new Set(adapter.schema.fields.map(f=>f.key));
    const values:Record<string,string>={};
    for(const [k,v] of Object.entries(body.values)) {
      if(!allowed.has(k)||typeof v!=="string"||v.length>4096) return json({error:"Invalid connector field: "+k},400);
      if(v.trim()) values[k]=v.trim();
    }
    let result: Awaited<ReturnType<typeof adapter.connect>>;
    try { result=await adapter.connect({request,env,actor,values},values); }
    catch(e) { return json({error:e instanceof Error?e.message:"Could not connect connector."},400); }
    try { await audit({request,env,actor,values},"integration_connected",adapter.id,"Success"); }
    catch { return json({error:"Connector credentials may have been saved, but the security audit could not be written. Refresh this integration before retrying.",saved:true,connectionState:"unknown"},503); }
    return json({saved:result.saved,connectionState:"saved_not_verified",configuredKeys:result.configuredKeys,secretsHidden:true});
  }
  if(match[2]==="test"&&request.method==="POST") {
    let result: AdapterResult;
    try { result=await adapter.test({request,env,actor,values:{}}); }
    catch(e) { return json({error:e instanceof Error?e.message:"Connector test failed."},502); }
    try { await audit({request,env,actor,values:{}},"integration_tested",adapter.id,result.ok?"Success":"Failure"); }
    catch { return json({error:"Connector test completed, but its security audit could not be written. Result is withheld until audit storage recovers."},503); }
    return json(result);
  }
  if(match[2]==="query"&&request.method==="POST") {
    let input:any; try { input=await request.json(); } catch { return json({error:"Invalid JSON body"},400); }
    let data: unknown;
    try { data=await adapter.query({request,env,actor,values:{}},input||{}); }
    catch(e) { return json({error:e instanceof Error?e.message:"Connector query failed."},400); }
    try { await audit({request,env,actor,values:{}},"integration_queried",adapter.id,"Success"); }
    catch { return json({error:"Connector query completed, but its security audit could not be written. Results are withheld until audit storage recovers."},503); }
    return json({data,queriedAt:now()});
  }
  return json({error:"Method not allowed"},405);
}
