[CmdletBinding()]
param(
  [string]$AllowedOrigin = 'https://sentinelx-api-gateway.aiman132046.workers.dev',
  [ValidateRange(1024,65535)][int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
$Collector = Join-Path $PSScriptRoot 'SentinelX_Local_Windows_Collector.ps1'
if (-not (Test-Path -LiteralPath $Collector)) { throw "Collector not found: $Collector" }
if ([string]::IsNullOrWhiteSpace($env:SENTINELX_WEBHOOK_URL) -or [string]::IsNullOrWhiteSpace($env:SENTINELX_WEBHOOK_KEY)) {
  throw 'SENTINELX_WEBHOOK_URL and SENTINELX_WEBHOOK_KEY must be available in this session.'
}
if ($AllowedOrigin -notmatch '^https://[a-zA-Z0-9.-]+$|^http://localhost(:[0-9]+)?$') { throw 'AllowedOrigin must be one exact HTTPS origin or localhost origin.' }
$script:CollectorProcess = $null
$script:LogDir = Join-Path $env:LOCALAPPDATA 'SentinelX'
New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "SentinelX Local Agent listening on http://127.0.0.1:$Port/"
Write-Host "Allowed GUI origin: $AllowedOrigin"
Write-Host 'Keep this window open. Press Ctrl+C to stop the local agent.'
function Send-Json($Response, [int]$Status, $Value) {
  $Response.StatusCode = $Status
  $Response.ContentType = 'application/json; charset=utf-8'
  $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Compress -Depth 5))
  $Response.ContentLength64 = $bytes.Length
  $Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $Response.Close()
}
function Get-CollectorStatus {
  if ($null -ne $script:CollectorProcess -and $script:CollectorProcess.HasExited) { $script:CollectorProcess = $null }
  [pscustomobject]@{
    agent = 'online'
    collector = $(if ($null -ne $script:CollectorProcess) { 'running' } else { 'stopped' })
    processId = $(if ($null -ne $script:CollectorProcess) { $script:CollectorProcess.Id } else { $null })
    eventScope = 'Windows Security Event ID 4625 only'
  }
}
try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $origin = $request.Headers['Origin']
    $hostHeader = $request.Headers['Host']
    if ($hostHeader -notin @("127.0.0.1:$Port", "localhost:$Port") -or $origin -ne $AllowedOrigin) {
      Send-Json $response 403 @{ error = 'Origin or host not allowed.' }
      continue
    }
    $response.Headers.Add('Access-Control-Allow-Origin', $AllowedOrigin)
    $response.Headers.Add('Vary', 'Origin')
    $response.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    $response.Headers.Add('Access-Control-Allow-Headers', 'Content-Type, X-SentinelX-Local-Agent')
    $response.Headers.Add('Access-Control-Allow-Private-Network', 'true')
    $response.Headers.Add('Cache-Control', 'no-store')
    if ($request.HttpMethod -eq 'OPTIONS') { $response.StatusCode = 204; $response.Close(); continue }
    if ($request.Headers['X-SentinelX-Local-Agent'] -ne 'sentinelx-gui-v1') {
      Send-Json $response 403 @{ error = 'Missing local-agent request header.' }
      continue
    }
    switch ("$($request.HttpMethod) $($request.Url.AbsolutePath)") {
      'GET /status' { Send-Json $response 200 (Get-CollectorStatus) }
      'POST /collector/start' {
        $status = Get-CollectorStatus
        if ($status.collector -eq 'running') { Send-Json $response 200 $status; continue }
        $stdout = Join-Path $script:LogDir 'collector.stdout.log'
        $stderr = Join-Path $script:LogDir 'collector.stderr.log'
        $argumentLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Collector + '" -Continuous'
        $script:CollectorProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentLine -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        Start-Sleep -Milliseconds 350
        $status = Get-CollectorStatus
        if ($status.collector -ne 'running') { Send-Json $response 500 @{ error = 'Collector exited during startup. Check the SentinelX collector.stderr.log file.' } }
        else { Send-Json $response 200 $status }
      }
      'POST /collector/stop' {
        if ($null -ne $script:CollectorProcess -and -not $script:CollectorProcess.HasExited) {
          Stop-Process -Id $script:CollectorProcess.Id -Force
          $script:CollectorProcess = $null
        }
        Send-Json $response 200 (Get-CollectorStatus)
      }
      default { Send-Json $response 404 @{ error = 'Unknown local-agent endpoint.' } }
    }
  }
} finally {
  if ($null -ne $script:CollectorProcess -and -not $script:CollectorProcess.HasExited) { Stop-Process -Id $script:CollectorProcess.Id -Force }
  if ($listener.IsListening) { $listener.Stop() }
  $listener.Close()
}
