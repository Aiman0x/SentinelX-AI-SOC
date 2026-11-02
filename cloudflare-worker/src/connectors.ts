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
}
const now = () => new Date().toISOString();
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
const enc = new TextEncoder();
const b64 = (v: Uint8Array) => btoa(String.fromCharCode(...v)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const unb64 = (v: string) => Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4-v.length%4)%4)), c => c.charCodeAt(0));
function storageKey(actor: Actor, id: string) { return actor.organization_id + ":" + actor.id + ":" + id; }
async function audit(context: AdapterContext, event: string, connectorId: string, outcome: string) {
  try {
    await context.env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
      .bind(crypto.randomUUID(),context.actor.organization_id,context.actor.id,"Human Analyst",event,connectorId,"Connector operation: "+connectorId,outcome).run();
  } catch { /* audit failures must not expose secrets or break provider checks */ }
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
    const response = await fetch(url, {...init, signal:controller.signal, redirect:"error"});
    const raw = await response.text();
    let data: any = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = { message: "Provider returned a non-JSON response." }; }
    return {response,data};
  } finally { clearTimeout(timeout); }
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
async function wazuhAuth(context: AdapterContext, values: Record<string,string>) {
  if (!publicHttps(values.apiUrl || "")) throw new Error("Wazuh requires a public HTTPS hostname (for example, a Cloudflare Tunnel protected by Access). Private IPs and plain HTTP are blocked.");
  if (!values.apiUser || !values.apiPassword) throw new Error("Wazuh API username and password are required.");
  const base = new URL(values.apiUrl);
  const root = base.origin + base.pathname.replace(/\/$/,"");
  const basic = btoa(unescape(encodeURIComponent(values.apiUser+":"+values.apiPassword)));
  const headers: Record<string,string> = {Authorization:"Basic "+basic,Accept:"application/json"};
  if (values.accessClientId && values.accessClientSecret) {
    headers["CF-Access-Client-Id"] = values.accessClientId;
    headers["CF-Access-Client-Secret"] = values.accessClientSecret;
  }
  const auth = await fetchJson(root+"/security/user/authenticate",{method:"POST",headers});
  if (!auth.response.ok) throw new Error(auth.response.status===401 ? "Wazuh rejected the API username/password." : "Wazuh authentication failed (HTTP "+auth.response.status+").");
  const token = auth.data?.data?.token;
  if (typeof token !== "string" || !token) throw new Error("Wazuh did not return an API token.");
  return {root,headers:{Authorization:"Bearer "+token,Accept:"application/json",...(values.accessClientId&&values.accessClientSecret?{"CF-Access-Client-Id":values.accessClientId,"CF-Access-Client-Secret":values.accessClientSecret}:{})}};
}
const field = (key:string,label:string,placeholder:string,type:FieldSchema["type"]="text",required=false,help?:string):FieldSchema => ({key,label,placeholder,type,required,help});
const wazuh: ToolAdapter = {
  id:"wazuh",name:"Wazuh",category:"SIEM",description:"Connect Wazuh Manager and Indexer: agent inventory plus actual security alert search.",
  schema:{version:"1.0",fields:[
    field("apiUrl","Wazuh Manager API URL","https://wazuh.example.com:55000","url",true,"Expose only through trusted HTTPS Cloudflare Tunnel / Access or a private bridge. Never open port 55000 publicly."),
    field("apiUser","Read-only Manager API username","sentinelx-readonly","text",true),
    field("apiPassword","Manager API password","Enter your Wazuh API password","password",true),
    field("indexerUrl","Wazuh Indexer HTTPS URL","https://wazuh-indexer.example.com:9200","url",true,"Required for querying real Wazuh alert documents. Keep the indexer private behind Cloudflare Access."),
    field("indexerUser","Read-only Indexer username","sentinelx-indexer-readonly","text",true),
    field("indexerPassword","Indexer password","Enter your Indexer password","password",true),
    field("accessClientId","Cloudflare Access Client ID","Service token ID","password"),
    field("accessClientSecret","Cloudflare Access Client Secret","Service token secret","password")
  ],query:{supported:true,description:"List agents, inspect an agent, retrieve Manager info, or search recent Wazuh alerts.",fields:[
    field("resource","Resource","agents, agent, manager or alerts","text",true),
    field("agentId","Agent ID (for resource=agent)","001"),
    field("limit","Alert result limit (1–100)","25")
  ]}},
  async connect(context,values) {
    const allowed=["apiUrl","apiUser","apiPassword","indexerUrl","indexerUser","indexerPassword","accessClientId","accessClientSecret"];
    for(const k of Object.keys(values)) if(!allowed.includes(k)) throw new Error("Unsupported Wazuh configuration field: "+k);
    if(!publicHttps(values.apiUrl||"")) throw new Error("A public HTTPS Wazuh Manager API URL is required. Use Cloudflare Tunnel/Access or a private bridge.");
    if(!values.apiUser||!values.apiPassword) throw new Error("Wazuh Manager API username and password are required.");
    if(!publicHttps(values.indexerUrl||"")||!values.indexerUser||!values.indexerPassword) throw new Error("A public HTTPS Wazuh Indexer URL and read-only username/password are required to query alerts.");
    if(Boolean(values.accessClientId)!==Boolean(values.accessClientSecret)) throw new Error("Provide both Cloudflare Access service token fields, or leave both blank.");
    const key=storageKey(context.actor,this.id),old=await context.env.INTEGRATION_CONFIGS.get(key);
    const previous=old?await unseal(old,context.env.CONFIG_ENCRYPTION_KEY,key):{};
    const merged={...previous,...values};
    await context.env.INTEGRATION_CONFIGS.put(key,await seal(merged,context.env.CONFIG_ENCRYPTION_KEY,key));
    return {saved:true,configuredKeys:Object.keys(merged)};
  },
  async test(context) {
    const at=now();
    try {
      const values=await saved(context,this.id);
      const auth=await wazuhAuth(context,values);
      const agents=await fetchJson(auth.root+"/agents?limit=1",{headers:auth.headers});
      if(!agents.response.ok) throw new Error("Wazuh Manager authenticated, but agent inventory returned HTTP "+agents.response.status+".");
      if(!publicHttps(values.indexerUrl||"")||!values.indexerUser||!values.indexerPassword) throw new Error("Wazuh Manager works, but Indexer URL and read-only credentials are required to verify alert search.");
      const indexer=new URL(values.indexerUrl);
      const indexerHeaders:Record<string,string>={Authorization:"Basic "+btoa(unescape(encodeURIComponent(values.indexerUser+":"+values.indexerPassword))),Accept:"application/json","Content-Type":"application/json"};
      if(values.accessClientId&&values.accessClientSecret){indexerHeaders["CF-Access-Client-Id"]=values.accessClientId;indexerHeaders["CF-Access-Client-Secret"]=values.accessClientSecret;}
      const alerts=await fetchJson(indexer.origin+(indexer.pathname.endsWith("/") ? indexer.pathname.slice(0,-1) : indexer.pathname)+"/wazuh-alerts-*/_search?size=1",{method:"POST",headers:indexerHeaders,body:JSON.stringify({size:1,query:{match_all:{}},sort:[{"@timestamp":{order:"desc"}}]})});
      if(!alerts.response.ok) throw new Error("Wazuh Manager works, but Indexer alert search failed (HTTP "+alerts.response.status+").");
      const result={ok:true,message:"Wazuh Manager API authenticated and Wazuh Indexer alert search succeeded.",checkedAt:at,details:{agentCount:agents.data?.data?.total_affected_items??null,alertIndexReachable:true}};
      await health(context,this.id,result); return result;
    } catch(e) {
      const result={ok:false,message:e instanceof Error?e.message:"Wazuh connection failed.",checkedAt:at};
      await health(context,this.id,result); return result;
    }
  },
  async query(context,input) {
    const values=await saved(context,this.id);
    const auth=await wazuhAuth(context,values);
    const resource=String(input.resource||"agents");
    if(resource==="alerts") {
      if(!publicHttps(values.indexerUrl||"")||!values.indexerUser||!values.indexerPassword) throw new Error("Wazuh Indexer read-only credentials are required.");
      const indexer=new URL(values.indexerUrl);
      const limit=Math.min(100,Math.max(1,Number(input.limit)||25));
      const headers:Record<string,string>={Authorization:"Basic "+btoa(unescape(encodeURIComponent(values.indexerUser+":"+values.indexerPassword))),Accept:"application/json","Content-Type":"application/json"};
      if(values.accessClientId&&values.accessClientSecret){headers["CF-Access-Client-Id"]=values.accessClientId;headers["CF-Access-Client-Secret"]=values.accessClientSecret;}
      const result=await fetchJson(indexer.origin+(indexer.pathname.endsWith("/") ? indexer.pathname.slice(0,-1) : indexer.pathname)+"/wazuh-alerts-*/_search",{method:"POST",headers,body:JSON.stringify({size:limit,track_total_hits:false,sort:[{"@timestamp":{order:"desc"}}],query:{match_all:{}}})});
      if(!result.response.ok) throw new Error("Wazuh alert search failed (HTTP "+result.response.status+").");
      return result.data;
    }
    let path="";
    if(resource==="agents") path="/agents?limit=100&select=id,name,status,ip,version,node_name";
    else if(resource==="agent") {
      const id=String(input.agentId||"");
      if(!/^[0-9]{3,8}$/.test(id)) throw new Error("Provide a valid Wazuh agent ID.");
      path="/agents/"+id;
    } else if(resource==="manager") path="/manager/info";
    else throw new Error("Supported Wazuh query resources are agents, agent, manager and alerts.");
    const result=await fetchJson(auth.root+path,{headers:auth.headers});
    if(!result.response.ok) throw new Error("Wazuh query failed (HTTP "+result.response.status+").");
    return result.data;
  }
};
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
function hostAdapter(id:"sysmon"|"suricata"|"zeek",name:string,description:string):ToolAdapter {
  const labels:Record<string,string>={sysmon:"Microsoft-Windows-Sysmon/Operational",suricata:"/var/log/suricata/eve.json",zeek:"/opt/zeek/logs/current"};
  return {
    id,name,category:id==="sysmon"?"Endpoint":"Network",description,
    schema:{version:"1.0",fields:[field("sensor","Sensor / host name","endpoint-01"),field("source","Telemetry source path or channel",labels[id])],query:{supported:true,description:"Retrieve recent tenant-scoped records reported by the enrolled host collector.",fields:[field("limit","Maximum records (1–100)","25")]}},
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
    async test(context) {
      const raw=await context.env.INTEGRATION_CONFIGS.get(context.actor.organization_id+":"+id+":health");
      if(!raw) return {ok:false,message:"No recent host collector health report. Install/enroll the collector on the sensor first.",checkedAt:now()};
      try { const h=JSON.parse(raw); const age=Date.now()-Date.parse(h.checkedAt||""); return {ok:h.ok===true&&h.status==="healthy"&&age<600000,message:age>=600000?"Collector health report is stale.":h.message||"Collector health report received.",checkedAt:now(),details:{collectorStatus:h.status,observedAt:h.checkedAt}}; }
      catch { return {ok:false,message:"Collector health report is invalid.",checkedAt:now()}; }
    },
    async query(context,input) {
      const limit=Math.min(100,Math.max(1,Number(input.limit)||25));
      const pattern="%"+id+"%";
      const rows=await context.env.DB.prepare("SELECT entity_type,source_table,source_record_id,payload_json,created_at FROM soc_records WHERE org_id=? AND (lower(entity_type) LIKE ? OR lower(source_table) LIKE ? OR lower(payload_json) LIKE ?) ORDER BY created_at DESC LIMIT ?").bind(context.actor.organization_id,pattern,pattern,pattern,limit).all();
      return {data:rows.results};
    }
  };
}
const activepieces: ToolAdapter = {
  id:"activepieces",name:"ActivePieces",category:"Orchestration",description:"Connect the SentinelX workflow bridge for event ingestion, triage and automation.",
  schema:{version:"1.0",fields:[],query:{supported:false,description:"Workflow execution remains controlled by SentinelX gateway routes."}},
  async connect() { return {saved:true,configuredKeys:[]}; },
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
const adapters: ToolAdapter[] = [
  activepieces,wazuh,
  hostAdapter("sysmon","Windows Sysmon","Windows process, network, registry and driver events delivered by the SentinelX host collector."),
  hostAdapter("suricata","Suricata","Network IDS/IPS alerts and protocol metadata from eve.json via a network sensor collector."),
  hostAdapter("zeek","Zeek","Network connection, DNS, HTTP and TLS metadata via a network sensor collector."),
  threatAdapter("virustotal"),threatAdapter("abuseipdb"),threatAdapter("urlscan")
];
export async function handleConnectorRoute(request:Request,env:ConnectorEnv,path:string):Promise<Response|null> {
  if(!path.startsWith("/api/integrations")) return null;
  const actor=await currentUser(request,env as Parameters<typeof currentUser>[1]);
  if(!actor) return json({error:"Authentication required"},401);
  if(request.method==="GET" && path==="/api/integrations") {
    const data=[];
    for(const adapter of adapters) {
      const key=storageKey(actor,adapter.id);
      const raw=await env.INTEGRATION_CONFIGS.get(key);
      const healthRaw=await env.INTEGRATION_CONFIGS.get(key+":health");
      const health=healthRaw?JSON.parse(healthRaw):null;
      let configuredKeys:string[]=[];
      if(raw) { try { configuredKeys=Object.keys(await unseal(raw,env.CONFIG_ENCRYPTION_KEY,key)); } catch {} }
      data.push({id:adapter.id,name:adapter.name,category:adapter.category,purpose:adapter.description,description:adapter.description,schema:adapter.schema,fields:adapter.schema.fields,configured:!!raw,configuredKeys,verified:health?.ok===true,state:health?.ok===true?"connected":raw?"disconnected":"not_configured",lastHealthCheck:health?.checkedAt||null,health:health?{ok:health.ok===true,message:health.message,checkedAt:health.checkedAt}:null});
    }
    return json({data,registryVersion:"1.0"});
  }
  const match=path.match(/^\/api\/integrations\/([a-z0-9_-]+)\/(schema|connect|test|query)$/);
  if(!match) return json({error:"Unknown integration route"},404);
  const adapter=adapters.find(x=>x.id===match[1]);
  if(!adapter) return json({error:"Unknown connector"},404);
  if(match[2]==="connect" && actor.role==="viewer") return json({error:"Viewer role cannot save connector credentials."},403);
  if(match[2]==="schema"&&request.method==="GET") return json({id:adapter.id,schema:adapter.schema});
  if(match[2]==="connect"&&request.method==="POST") {
    let body:any; try { body=await request.json(); } catch { return json({error:"Invalid JSON body"},400); }
    if(!body?.values||typeof body.values!=="object"||Array.isArray(body.values)) return json({error:"values object required"},400);
    const allowed=new Set(adapter.schema.fields.map(f=>f.key));
    const values:Record<string,string>={};
    for(const [k,v] of Object.entries(body.values)) {
      if(!allowed.has(k)||typeof v!=="string"||v.length>4096) return json({error:"Invalid connector field: "+k},400);
      if(v.trim()) values[k]=v.trim();
    }
    try { const result=await adapter.connect({request,env,actor,values},values); await audit({request,env,actor,values},"integration_connected",adapter.id,"Success"); return json({connected:result.saved,saved:true,configuredKeys:result.configuredKeys,secretsHidden:true}); }
    catch(e) { return json({error:e instanceof Error?e.message:"Could not connect connector."},400); }
  }
  if(match[2]==="test"&&request.method==="POST") {
    const result=await adapter.test({request,env,actor,values:{}});
    await audit({request,env,actor,values:{}},"integration_tested",adapter.id,result.ok?"Success":"Failure");
    return json(result);
  }
  if(match[2]==="query"&&request.method==="POST") {
    let input:any; try { input=await request.json(); } catch { return json({error:"Invalid JSON body"},400); }
    try { const data=await adapter.query({request,env,actor,values:{}},input||{}); await audit({request,env,actor,values:{}},"integration_queried",adapter.id,"Success"); return json({data,queriedAt:now()}); }
    catch(e) { return json({error:e instanceof Error?e.message:"Connector query failed."},400); }
  }
  return json({error:"Method not allowed"},405);
}
