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

async function dispatchLocalBridge(context: AdapterContext, connectorId: string, operation: "test" | "query", config: Record<string,string>, input: Record<string,unknown> = {}) {
  const bridge = await context.env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND bridge_enabled=1 AND revoked_at IS NULL AND last_seen_at>=? ORDER BY last_seen_at DESC LIMIT 1")
    .bind(context.actor.organization_id, new Date(Date.now()-90_000).toISOString()).first<{id:string}>();
  if (!bridge) throw new Error("No online SentinelX Local Bridge is connected to this workspace. Enroll and start a bridge on a machine that can reach Wazuh.");
  const taskId = crypto.randomUUID();
  const nowAt = new Date();
  const expiresAt = new Date(nowAt.getTime()+30_000).toISOString();
  await context.env.DB.prepare("INSERT INTO bridge_tasks(id,org_id,collector_id,actor_id,connector_id,request_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,'queued',?,?)")
    .bind(taskId, context.actor.organization_id, bridge.id, context.actor.id, connectorId, JSON.stringify({operation,config,input}), nowAt.toISOString(), expiresAt).run();
  const deadline = Date.now()+25_000;
  while (Date.now()<deadline) {
    const row = await context.env.DB.prepare("SELECT status,result_json FROM bridge_tasks WHERE id=? AND org_id=? AND collector_id=?")
      .bind(taskId, context.actor.organization_id, bridge.id).first<{status:string;result_json:string|null}>();
    if (row?.status === "completed" || row?.status === "failed") {
      if (!row.result_json) throw new Error("Local Bridge returned an empty result.");
      const result = JSON.parse(row.result_json) as {ok:boolean;message:string;data?:unknown};
      if (!result.ok) throw new Error(result.message || "Local Bridge tool query failed.");
      return result.data ?? {message:result.message};
    }
    if (row?.status === "expired") throw new Error("Local Bridge task expired before execution.");
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  await context.env.DB.prepare("UPDATE bridge_tasks SET status='expired' WHERE id=? AND status IN ('queued','claimed')").bind(taskId).run();
  throw new Error("Local Bridge did not respond within 25 seconds. Check that the bridge process is running.");
}
function validBridgeEndpoint(value: string, allowedPort: string) {
  try {
    const u = new URL(value);
    if (!["http:","https:"].includes(u.protocol) || u.username || u.password || u.search || u.hash) return false;
    if (!u.hostname || ["169.254.169.254","metadata.google.internal","metadata.azure.internal"].includes(u.hostname.toLowerCase())) return false;
    return !u.port || u.port === allowedPort;
  } catch { return false; }
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
    field("connectionMode","Connection mode","direct","text",true,"direct = public HTTPS API; local_bridge = private/local API reached by your enrolled SentinelX Bridge."),
    field("apiUrl","Wazuh Manager API URL","https://wazuh.example.com:55000","url",true,"Direct mode requires public HTTPS. Local Bridge mode accepts a private/local Wazuh URL reachable from the bridge machine; never expose port 55000 publicly."),
    field("apiUser","Read-only Manager API username","sentinelx-readonly","text",true),
    field("apiPassword","Manager API password","Enter your Wazuh API password","password",true),
    field("indexerUrl","Wazuh Indexer URL","https://wazuh-indexer.example.com:9200","url",true,"Required for alert search. In Local Bridge mode this may be a private/local address reachable from the bridge."),
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
    const mode=values.connectionMode||"direct";
    if(mode!=="direct"&&mode!=="local_bridge") throw new Error("Choose direct or local_bridge connection mode.");
    if(mode==="direct"&&!publicHttps(values.apiUrl||"")) throw new Error("Direct Wazuh connections require a public HTTPS hostname. Choose Local Bridge for private/local addresses.");
    if(mode==="local_bridge"&&(!validBridgeEndpoint(values.apiUrl||"","55000")||!validBridgeEndpoint(values.indexerUrl||"","9200"))) throw new Error("Local Bridge URLs must use HTTP/HTTPS and the Wazuh Manager port 55000 / Indexer port 9200.");
    if(!values.apiUser||!values.apiPassword) throw new Error("Wazuh Manager API username and password are required.");
    if(mode==="direct"&&!publicHttps(values.indexerUrl||"")) throw new Error("Direct Wazuh connections require a public HTTPS Indexer hostname.");
    if(!values.indexerUrl||!values.indexerUser||!values.indexerPassword) throw new Error("Wazuh Indexer URL and read-only username/password are required to query alerts.");
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
      if((values.connectionMode||"direct")==="local_bridge") {
        const data=await dispatchLocalBridge(context,this.id,"test",values,{});
        const result={ok:true,message:"Wazuh Manager verified through the SentinelX Local Bridge.",checkedAt:at,details:{bridge:true}};
        await health(context,this.id,result); return result;
      }
      const auth=await wazuhAuth(context,values);
      const agents=await fetchJson(auth.root+"/agents?limit=1",{headers:auth.headers});
      if(!agents.response.ok) throw new Error("Wazuh Manager authenticated, but agent inventory returned HTTP "+agents.response.status+".");
      if(!publicHttps(values.indexerUrl||"")||!values.indexerUser||!values.indexerPassword) throw new Error("Wazuh Manager works, but Indexer URL and read-only credentials are required to verify alert search.");
      const indexer=new URL(values.indexerUrl);
      const indexerHeaders:Record<string,string>={Authorization:"Basic "+btoa(unescape(encodeURIComponent(values.indexerUser+":"+values.indexerPassword))),Accept:"application/json","Content-Type":"application/json"};
      if(values.accessClientId&&values.accessClientSecret){indexerHeaders["CF-Access-Client-Id"]=values.accessClientId;indexerHeaders["CF-Access-Client-Secret"]=values.accessClientSecret;}
      const alerts=await fetchJson(indexer.origin+(indexer.pathname.endsWith("/") ? indexer.pathname.slice(0,-1) : indexer.pathname)+"/wazuh-alerts-*/_search?size=1",{method:"POST",headers:indexerHeaders,body:JSON.stringify({size:1,query:{match_all:{}},sort:[{"timestamp":{order:"desc"}}]})});
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
    if((values.connectionMode||"direct")==="local_bridge") return dispatchLocalBridge(context,this.id,"query",values,input);
    const auth=await wazuhAuth(context,values);
    const resource=String(input.resource||"agents");
    if(resource==="alerts") {
      if(!publicHttps(values.indexerUrl||"")||!values.indexerUser||!values.indexerPassword) throw new Error("Wazuh Indexer read-only credentials are required.");
      const indexer=new URL(values.indexerUrl);
      const limit=Math.min(100,Math.max(1,Number(input.limit)||25));
      const headers:Record<string,string>={Authorization:"Basic "+btoa(unescape(encodeURIComponent(values.indexerUser+":"+values.indexerPassword))),Accept:"application/json","Content-Type":"application/json"};
      if(values.accessClientId&&values.accessClientSecret){headers["CF-Access-Client-Id"]=values.accessClientId;headers["CF-Access-Client-Secret"]=values.accessClientSecret;}
      const result=await fetchJson(indexer.origin+(indexer.pathname.endsWith("/") ? indexer.pathname.slice(0,-1) : indexer.pathname)+"/wazuh-alerts-*/_search",{method:"POST",headers,body:JSON.stringify({size:limit,track_total_hits:false,sort:[{"timestamp":{order:"desc"}}],query:{match_all:{}}})});
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
  activepieces,wazuh,
  hostAdapter("sysmon","Windows Sysmon","Windows process, network, registry and driver events delivered by the SentinelX host collector."),
  hostAdapter("suricata","Suricata","Network IDS/IPS alerts and protocol metadata from eve.json via a network sensor collector."),
  hostAdapter("zeek","Zeek","Network connection, DNS, HTTP and TLS metadata via a network sensor collector."),
  threatAdapter("virustotal"),threatAdapter("abuseipdb"),threatAdapter("urlscan")
];

export async function getAgentToolCatalog(request: Request, env: ConnectorEnv) {
  const actor = await currentUser(request, env as Parameters<typeof currentUser>[1]);
  if (!actor) throw new Error("Authentication required");
  const tools = [];
  for (const adapter of adapters) {
    if (!adapter.schema.query.supported) continue;
    const key = storageKey(actor, adapter.id);
    const configured = Boolean(await env.INTEGRATION_CONFIGS.get(key));
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
  if (!(await env.INTEGRATION_CONFIGS.get(key))) throw new Error("This tool is not connected for your user account.");
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
    try { const result=await adapter.connect({request,env,actor,values},values); await audit({request,env,actor,values},"integration_connected",adapter.id,"Success"); return json({saved:result.saved,connectionState:"saved_not_verified",configuredKeys:result.configuredKeys,secretsHidden:true}); }
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
