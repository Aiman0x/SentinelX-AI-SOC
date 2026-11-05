package main

import (
  "bytes"
  "context"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "net/http"
  "net/url"
  "strings"
  "time"
)

type MCPTool struct {
  Name string `json:"name"`
  Description string `json:"description,omitempty"`
  InputSchema map[string]any `json:"inputSchema,omitempty"`
  Annotations struct { ReadOnlyHint bool `json:"readOnlyHint"` } `json:"annotations,omitempty"`
}
type MCPEnvelope struct {
  JSONRPC string `json:"jsonrpc"`
  ID any `json:"id,omitempty"`
  Method string `json:"method,omitempty"`
  Params any `json:"params,omitempty"`
  Result struct { ProtocolVersion string `json:"protocolVersion,omitempty"`; Tools []MCPTool `json:"tools,omitempty"`; Content []any `json:"content,omitempty"`; IsError bool `json:"isError,omitempty"` } `json:"result,omitempty"`
  Error *struct { Code int `json:"code"`; Message string `json:"message"` } `json:"error,omitempty"`
}
type MCPClient struct { endpoint, token, session string; protocol string }
func newMCPClient(cfg map[string]string) (*MCPClient,error) {
  endpoint:=strings.TrimSpace(cfg["serverUrl"])
  u,err:=url.Parse(endpoint)
  if err!=nil || (u.Scheme!="https"&&u.Scheme!="http") || u.Host=="" || u.User!=nil || u.RawQuery!="" || u.Fragment!="" {
    return nil,errors.New("MCP server URL must be a valid HTTP/HTTPS endpoint without embedded credentials, query or fragment")
  }
  if u.Hostname()=="169.254.169.254" || strings.Contains(strings.ToLower(u.Hostname()),"metadata.") {
    return nil,errors.New("Cloud metadata endpoints are blocked")
  }
  return &MCPClient{endpoint:endpoint,token:cfg["bearerToken"]},nil
}
func (c *MCPClient) post(ctx context.Context, payload any) (MCPEnvelope,error) {
  var out MCPEnvelope
  raw,err:=json.Marshal(payload); if err!=nil{return out,err}
  req,err:=http.NewRequestWithContext(ctx,"POST",c.endpoint,bytes.NewReader(raw)); if err!=nil{return out,err}
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Accept","application/json, text/event-stream")
  if c.protocol!="" { req.Header.Set("MCP-Protocol-Version",c.protocol) }
  if c.token!="" { req.Header.Set("Authorization","Bearer "+c.token) }
  if c.session!="" { req.Header.Set("Mcp-Session-Id",c.session) }
  resp,err:=client.Do(req); if err!=nil{return out,err}; defer resp.Body.Close()
  if resp.StatusCode<200||resp.StatusCode>=300 { return out,fmt.Errorf("MCP server returned HTTP %d",resp.StatusCode) }
  if sid:=resp.Header.Get("Mcp-Session-Id");sid!="" { c.session=sid }
  body,err:=io.ReadAll(io.LimitReader(resp.Body,2<<20)); if err!=nil{return out,err}
  contentType:=strings.ToLower(resp.Header.Get("Content-Type"))
  if strings.Contains(contentType,"text/event-stream") {
    for _,line:=range strings.Split(string(body),"\n") {
      line=strings.TrimSpace(line)
      if strings.HasPrefix(line,"data:") {
        candidate:=strings.TrimSpace(strings.TrimPrefix(line,"data:"))
        if json.Unmarshal([]byte(candidate),&out)==nil && out.ID!=nil { return out,nil }
      }
    }
    return out,errors.New("MCP event stream contained no JSON-RPC response")
  }
  if err:=json.Unmarshal(body,&out);err!=nil{return out,fmt.Errorf("invalid MCP JSON-RPC response: %w",err)}
  if out.Error!=nil{return out,fmt.Errorf("MCP error %d: %s",out.Error.Code,out.Error.Message)}
  return out,nil
}
func (c *MCPClient) initialize(ctx context.Context) error {
  response,err:=c.post(ctx,map[string]any{"jsonrpc":"2.0","id":1,"method":"initialize","params":map[string]any{"protocolVersion":c.protocol,"capabilities":map[string]any{},"clientInfo":map[string]any{"name":"SentinelX Local Bridge","version":"0.2.0"}}})
  if err!=nil{return err}
  if response.Result.ProtocolVersion!="" { c.protocol=response.Result.ProtocolVersion } else { c.protocol="2025-06-18" }
  _,err=c.post(ctx,map[string]any{"jsonrpc":"2.0","method":"notifications/initialized","params":map[string]any{}})
  // Notifications may legitimately return HTTP 202/204 without a JSON body.
  if err!=nil && !strings.Contains(err.Error(),"invalid MCP JSON-RPC response") { return err }
  return nil
}
func (c *MCPClient) listTools(ctx context.Context) ([]MCPTool,error) {
  response,err:=c.post(ctx,map[string]any{"jsonrpc":"2.0","id":2,"method":"tools/list","params":map[string]any{}})
  if err!=nil{return nil,err}
  return response.Result.Tools,nil
}
func executeMCP(task Task) Result {
  c,err:=newMCPClient(task.Config); if err!=nil{return Result{OK:false,Message:err.Error()}}
  ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second); defer cancel()
  if err=c.initialize(ctx);err!=nil{return Result{OK:false,Message:"MCP initialize failed: "+err.Error()}}
  tools,err:=c.listTools(ctx);if err!=nil{return Result{OK:false,Message:"MCP tools/list failed: "+err.Error()}}
  if task.Operation=="test" || task.Input["action"]=="list" {
    safe:=make([]map[string]any,0,len(tools))
    for _,tool:=range tools { safe=append(safe,map[string]any{"name":tool.Name,"description":tool.Description,"inputSchema":tool.InputSchema,"readOnly":tool.Annotations.ReadOnlyHint}) }
    return Result{OK:true,Message:fmt.Sprintf("MCP server discovered %d tools.",len(tools)),Data:map[string]any{"tools":safe,"total":len(tools),"readOnlyTools":countReadOnly(tools)}}
  }
  if task.Operation!="query" || task.Input["action"]!="call" { return Result{OK:false,Message:"Unsupported MCP operation"} }
  name,_:=task.Input["toolName"].(string)
  if name=="" || len(name)>128 { return Result{OK:false,Message:"A valid MCP tool name is required"} }
  var selected *MCPTool
  for i:=range tools { if tools[i].Name==name { selected=&tools[i];break } }
  if selected==nil { return Result{OK:false,Message:"MCP tool was not found; refresh the discovered tool list"} }
  if !selected.Annotations.ReadOnlyHint { return Result{OK:false,Message:"Blocked: SentinelX only executes MCP tools explicitly annotated readOnlyHint=true"} }
  args,ok:=task.Input["arguments"].(map[string]any);if !ok { args=map[string]any{} }
  response,err:=c.post(ctx,map[string]any{"jsonrpc":"2.0","id":3,"method":"tools/call","params":map[string]any{"name":name,"arguments":args}})
  if err!=nil{return Result{OK:false,Message:"MCP tool call failed: "+err.Error()}}
  if response.Result.IsError { return Result{OK:false,Message:"MCP server reported a tool execution error",Data:response.Result.Content} }
  return Result{OK:true,Message:"Read-only MCP tool executed.",Data:map[string]any{"tool":name,"content":response.Result.Content}}
}
func countReadOnly(tools []MCPTool) int { n:=0;for _,t:=range tools { if t.Annotations.ReadOnlyHint { n++ } };return n }
