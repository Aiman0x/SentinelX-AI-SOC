import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, isBackendConfigured } from "../services/apiClient";
import { useAuth } from "../context/AuthContext";

type Approval = { approval_id:string; case_id:string|null; action_type:string; target_asset:string|null; proposed_action:string; reason_evidence:string; risk_level:string; requested_by:string; requested_by_actor_id?:string|null; status:string; approved_by:string|null; approved_by_actor_id?:string|null; requested_at:string; decision_at:string|null; execution_status:string; execution_result:string|null; expires_at:string|null; execution_mode:string; verification_result:string|null };
export function ResponseApprovalPanel() {
  const { user } = useAuth();
  const [rows,setRows]=useState<Approval[]>([]);
  const [target,setTarget]=useState("");
  const [reason,setReason]=useState("");
  const [caseId,setCaseId]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const reload=useCallback(async()=>{if(!isBackendConfigured)return;try{const r=await apiGet<{data:Approval[]}>("/api/approvals");setRows(r.data||[]);}catch(e){setError(e instanceof Error?e.message:"Could not load approvals.");}},[]);
  useEffect(()=>{void reload();},[reload]);
  const requestBlock=async()=>{
    setBusy(true);setError("");setNotice("");
    try{
      const r=await apiPost<{approval:{approvalId:string}}>("/api/approvals",{actionType:"block_ip",targetAsset:target.trim(),proposedAction:"Block this exact IP address using the connected Cloudflare zone.",reasonEvidence:reason.trim(),riskLevel:"High",caseId:caseId.trim()||undefined});
      setNotice("Approval requested: "+r.approval.approvalId+". No action has run. A different owner/admin must approve it.");
      setTarget("");setReason("");setCaseId("");await reload();
    }catch(e){setError(e instanceof Error?e.message:"Could not request approval.");}finally{setBusy(false);}
  };
  const decide=async(id:string,decision:"Approved"|"Rejected")=>{
    setBusy(true);setError("");setNotice("");
    try{await apiPost("/api/approvals/"+encodeURIComponent(id)+"/decision",{decision});setNotice("Decision recorded. No real action is executed until the separate Execute step.");await reload();}
    catch(e){setError(e instanceof Error?e.message:"Decision failed.");}finally{setBusy(false);}
  };
  const execute=async(id:string)=>{
    if(!window.confirm("This will create a REAL Cloudflare IP block rule in your connected zone. Confirm the target and expected service impact before continuing."))return;
    setBusy(true);setError("");setNotice("");
    try{const r=await apiPost<{executed:boolean;verified:boolean;target:string;providerRuleId:string}>("/api/response/execute/"+encodeURIComponent(id),{});setNotice("Execution result for "+id+": "+(r.verified?"provider read-back verified":"created but verification inconclusive")+". Target "+r.target+"; rule "+r.providerRuleId+".");await reload();}
    catch(e){setError(e instanceof Error?e.message:"Execution failed; inspect provider and audit logs before retrying.");await reload();}finally{setBusy(false);}
  };
  return <section className="panel mt-5 space-y-3 p-4">
    <div><h2 className="text-sm font-semibold">Approval-Gated Response</h2><p className="mt-1 text-[11px] text-sx-mute">Currently supported real action: Cloudflare IP block. Requester and approver must be different accounts. Approval expires after 15 minutes. Host isolation is not enabled yet.</p></div>
    {!isBackendConfigured&&<p className="text-xs text-sx-warn">Connect the SentinelX backend first.</p>}
    <div className="grid gap-2 md:grid-cols-3">
      <label className="text-xs text-sx-mute">Exact IPv4/IPv6 address<input className="input mt-1 w-full" value={target} onChange={e=>setTarget(e.target.value)} placeholder="203.0.113.10" maxLength={64}/></label>
      <label className="text-xs text-sx-mute">Related case ID (optional)<input className="input mt-1 w-full" value={caseId} onChange={e=>setCaseId(e.target.value)} placeholder="SX-..." maxLength={120}/></label>
      <label className="text-xs text-sx-mute">Evidence / reason<input className="input mt-1 w-full" value={reason} onChange={e=>setReason(e.target.value)} placeholder="Why this IP should be blocked" maxLength={1000}/></label>
    </div>
    <button className="btn btn-primary btn-sm" disabled={!isBackendConfigured||busy||!target.trim()||!reason.trim()} onClick={()=>void requestBlock()}>{busy?"Working…":"Request IP block approval"}</button>
    {error&&<p role="alert" className="text-xs text-sx-red">{error}</p>}{notice&&<p role="status" className="text-xs text-sx-gold">{notice}</p>}
    <div className="space-y-2">
      {rows.map(a=><article key={a.approval_id} className="rounded border border-sx-line p-3">
        <div className="flex flex-wrap items-start justify-between gap-2"><div><div className="mono text-[10px] text-sx-gold">{a.approval_id}</div><p className="mt-1 text-xs font-semibold">{a.action_type} · {a.target_asset||"target unspecified"}</p><p className="mt-1 text-[10px] text-sx-mute">{a.status} · {a.execution_status} · expires {a.expires_at?new Date(a.expires_at).toLocaleString():"not set"}</p></div><span className="rounded border border-sx-line px-2 py-1 text-[10px]">{a.risk_level}</span></div>
        <p className="mt-2 text-xs">{a.reason_evidence}</p>
        <p className="mt-1 text-[10px] text-sx-mute">Requested by {a.requested_by}; approved by {a.approved_by||"—"}. {a.verification_result||""}</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {a.status==="Pending Approval"&&<><button className="btn btn-secondary btn-sm" disabled={busy||a.requested_by_actor_id===user?.id} onClick={()=>void decide(a.approval_id,"Approved")}>Approve</button><button className="btn btn-secondary btn-sm" disabled={busy} onClick={()=>void decide(a.approval_id,"Rejected")}>Reject</button></>}
          {a.status==="Approved"&&a.execution_status==="Not Executed"&&<button className="btn btn-primary btn-sm" disabled={busy||a.approved_by_actor_id!==user?.id} onClick={()=>void execute(a.approval_id)}>Execute approved IP block</button>}
        </div>
      </article>)}
      {rows.length===0&&<p className="text-xs text-sx-mute">No response approvals yet.</p>}
    </div>
  </section>;
}
