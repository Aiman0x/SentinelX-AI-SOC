package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	GatewayURL string `json:"gateway_url"`
	Token      string `json:"token"`
	PollMS     int    `json:"poll_ms"`
}
type Task struct {
	ID          string            `json:"id"`
	ConnectorID string            `json:"connectorId"`
	Operation   string            `json:"operation"`
	Config      map[string]string `json:"config"`
	Input       map[string]any    `json:"input"`
}
type APIResponse struct {
	Task *Task `json:"task"`
}
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
type WazuhAuth struct {
	Root    string
	Token   string
	Headers http.Header
}
var client = &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

func main() {
	configPath := flag.String("config", "sentinelx-bridge.json", "Path to bridge config JSON")
	flag.Parse()
	cfg, err := loadConfig(*configPath)
	if err != nil { fatal(err) }
	if cfg.PollMS < 500 { cfg.PollMS = 1500 }
	if !strings.HasPrefix(cfg.GatewayURL, "https://") { fatal(errors.New("gateway_url must use HTTPS")) }
	if len(cfg.Token) < 40 { fatal(errors.New("bridge token is missing or invalid")) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Println("SentinelX Local Bridge starting; outbound-only mode enabled.")
	for ctx.Err() == nil {
		if err := pollOnce(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "bridge:", err)
			select { case <-ctx.Done(): return; case <-time.After(3*time.Second): }
			continue
		}
		select { case <-ctx.Done(): return; case <-time.After(time.Duration(cfg.PollMS)*time.Millisecond): }
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path); if err != nil { return cfg, err }
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}
func request(ctx context.Context, method, url, token string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil { b, err := json.Marshal(body); if err != nil { return nil,0,err }; reader = bytes.NewReader(b) }
	req, err := http.NewRequestWithContext(ctx, method, url, reader); if err != nil { return nil,0,err }
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil { req.Header.Set("Content-Type", "application/json") }
	resp, err := client.Do(req); if err != nil { return nil,0,err }; defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)); return b, resp.StatusCode, err
}
func pollOnce(ctx context.Context, cfg Config) error {
	base := strings.TrimRight(cfg.GatewayURL, "/")
	b, status, err := request(ctx, "GET", base+"/api/bridge/poll", cfg.Token, nil)
	if err != nil { return err }; if status == 204 { return nil }; if status != 200 { return fmt.Errorf("poll rejected (HTTP %d): %s",status,string(b)) }
	var response APIResponse
	if err := json.Unmarshal(b,&response); err != nil { return err }
	if response.Task == nil { return nil }
	result := execute(*response.Task)
	_, status, err = request(ctx,"POST",base+"/api/bridge/result/"+response.Task.ID,cfg.Token,result)
	if err != nil { return err }; if status != 200 { return fmt.Errorf("result rejected (HTTP %d)",status) }
	return nil
}
func execute(task Task) Result {
	if task.ConnectorID != "wazuh" { return Result{OK:false,Message:"This bridge build currently supports Wazuh only; MCP adapter support is the next connector module."} }
	if task.Operation != "query" && task.Operation != "test" { return Result{OK:false,Message:"Unsupported read-only operation"} }
	auth, err := authenticate(task.Config); if err != nil { return Result{OK:false,Message:err.Error()} }
	if task.Operation == "test" {
		b, status, err := do(auth.Root+"/agents?limit=1", "GET", auth.Headers, nil)
		if err != nil { return Result{OK:false,Message:err.Error()} }; if status < 200 || status >= 300 { return Result{OK:false,Message:fmt.Sprintf("Wazuh Manager returned HTTP %d",status)} }
		return Result{OK:true,Message:"Local Wazuh Manager API authenticated.",Data:json.RawMessage(b)}
	}
	resource, _ := task.Input["resource"].(string); if resource == "" { resource = "agents" }
	path := ""
	switch resource {
	case "agents": path = "/agents?limit=100&select=id,name,status,ip,version,node_name"
	case "manager": path = "/manager/info"
	case "agent":
		id, _ := task.Input["agentId"].(string)
		if len(id)<3 || len(id)>8 { return Result{OK:false,Message:"Valid Wazuh agent ID required"} }
		for _, ch := range id { if ch<'0' || ch>'9' { return Result{OK:false,Message:"Invalid Wazuh agent ID"} } }
		path = "/agents/"+id
	case "alerts":
		indexer := strings.TrimRight(task.Config["indexerUrl"],"/")
		if !strings.HasPrefix(indexer,"https://") && !strings.HasPrefix(indexer,"http://") { return Result{OK:false,Message:"Indexer URL is required"} }
		limit := 25
		if n, ok := task.Input["limit"].(float64); ok && n>=1 && n<=100 { limit=int(n) }
		headers := make(http.Header); headers.Set("Authorization","Basic "+basic(task.Config["indexerUser"],task.Config["indexerPassword"])); headers.Set("Content-Type","application/json")
		if task.Config["accessClientId"]!="" { headers.Set("CF-Access-Client-Id",task.Config["accessClientId"]); headers.Set("CF-Access-Client-Secret",task.Config["accessClientSecret"]) }
		body := map[string]any{"size":limit,"track_total_hits":false,"sort":[]any{map[string]any{"timestamp":map[string]any{"order":"desc"}}},"query":map[string]any{"match_all":map[string]any{}}}
		b,status,err:=do(indexer+"/wazuh-alerts-*/_search","POST",headers,body)
		if err!=nil{return Result{OK:false,Message:err.Error()}}; if status<200||status>=300{return Result{OK:false,Message:fmt.Sprintf("Wazuh Indexer returned HTTP %d",status)}}
		return Result{OK:true,Message:"Wazuh alerts retrieved through local bridge.",Data:json.RawMessage(b)}
	default: return Result{OK:false,Message:"Unsupported Wazuh read-only resource"}
	}
	b,status,err:=do(auth.Root+path,"GET",auth.Headers,nil)
	if err!=nil{return Result{OK:false,Message:err.Error()}}; if status<200||status>=300{return Result{OK:false,Message:fmt.Sprintf("Wazuh API returned HTTP %d",status)}}
	return Result{OK:true,Message:"Wazuh read-only query completed.",Data:json.RawMessage(b)}
}
func authenticate(cfg map[string]string) (WazuhAuth,error) {
	apiURL:=strings.TrimRight(cfg["apiUrl"],"/")
	if (!strings.HasPrefix(apiURL,"https://") && !strings.HasPrefix(apiURL,"http://")) || cfg["apiUser"]=="" || cfg["apiPassword"]=="" { return WazuhAuth{},errors.New("Wazuh Manager URL and read-only credentials are required") }
	headers:=make(http.Header); headers.Set("Authorization",basic(cfg["apiUser"],cfg["apiPassword"])); headers.Set("Accept","application/json")
	if cfg["accessClientId"]!="" { headers.Set("CF-Access-Client-Id",cfg["accessClientId"]); headers.Set("CF-Access-Client-Secret",cfg["accessClientSecret"]) }
	b,status,err:=do(apiURL+"/security/user/authenticate","POST",headers,nil); if err!=nil{return WazuhAuth{},err}; if status<200||status>=300{return WazuhAuth{},fmt.Errorf("Wazuh authentication failed (HTTP %d)",status)}
	var payload struct { Data struct { Token string `json:"token"` } `json:"data"` }
	if err=json.Unmarshal(b,&payload);err!=nil||payload.Data.Token=="" { return WazuhAuth{},errors.New("Wazuh did not return an API token") }
	headers.Set("Authorization","Bearer "+payload.Data.Token)
	return WazuhAuth{Root:apiURL,Token:payload.Data.Token,Headers:headers},nil
}
func basic(user,password string) string { return "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)) }
func b64(b []byte) string {
	const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i:=0;i<len(b);i+=3 { a:=int(b[i]); c:=0; d:=0; rem:=len(b)-i; if rem>1{c=int(b[i+1])}; if rem>2{d=int(b[i+2])}; out.WriteByte(alphabet[a>>2]); out.WriteByte(alphabet[((a&3)<<4)|(c>>4)]); if rem>1{out.WriteByte(alphabet[((c&15)<<2)|(d>>6)])}else{out.WriteByte('=')}; if rem>2{out.WriteByte(alphabet[d&63])}else{out.WriteByte('=')} }
	return out.String()
}
func do(url,method string,headers http.Header,body any)([]byte,int,error){
	var reader io.Reader
	if body!=nil { b,err:=json.Marshal(body);if err!=nil{return nil,0,err};reader=bytes.NewReader(b) }
	req,err:=http.NewRequest(method,url,reader);if err!=nil{return nil,0,err}
	for k,values:=range headers { for _,v:=range values { req.Header.Add(k,v) } }
	if body!=nil{req.Header.Set("Content-Type","application/json")}
	resp,err:=client.Do(req);if err!=nil{return nil,0,err};defer resp.Body.Close()
	b,err:=io.ReadAll(io.LimitReader(resp.Body,1<<20));return b,resp.StatusCode,err
}
func fatal(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}

