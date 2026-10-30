# SentinelX read-only Windows Security 4625 collector
# Requires an elevated PowerShell session with permission to read the Security log.
# Reads failed logons only. It does not modify Windows security settings or respond to incidents.

[CmdletBinding()]
param(
    [switch]$Continuous,
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 30,
    [ValidateRange(1, 1440)][int]$InitialLookbackMinutes = 15
)

$ErrorActionPreference = 'Stop'
$WebhookUrl = $env:SENTINELX_WEBHOOK_URL
$WebhookKey = $env:SENTINELX_WEBHOOK_KEY

if ([string]::IsNullOrWhiteSpace($WebhookUrl) -or [string]::IsNullOrWhiteSpace($WebhookKey)) {
    throw 'Set SENTINELX_WEBHOOK_URL and SENTINELX_WEBHOOK_KEY in the current PowerShell session before running the collector.'
}
if ($WebhookUrl -notmatch '^https://') { throw 'SENTINELX_WEBHOOK_URL must use HTTPS.' }

$StateDirectory = Join-Path $env:LOCALAPPDATA 'SentinelX'
$CheckpointPath = Join-Path $StateDirectory 'last-security-record-id.txt'
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null

function Get-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)

    [xml]$xml = $Record.ToXml()
    $fields = @{}
    foreach ($node in @($xml.Event.EventData.Data)) {
        if ($null -ne $node -and -not [string]::IsNullOrWhiteSpace([string]$node.Name)) {
            $fields[[string]$node.Name] = [string]$node.InnerText
        }
    }

    $system = $xml.Event.System
    $time = [DateTime]::Parse([string]$system.TimeCreated.SystemTime).ToUniversalTime()
    $computer = [string]$system.Computer
    if ([string]::IsNullOrWhiteSpace($computer)) { $computer = $env:COMPUTERNAME }

    $targetUser = [string]$fields['TargetUserName']
    if ([string]::IsNullOrWhiteSpace($targetUser) -or $targetUser -eq '-') {
        $targetUser = [string]$fields['SubjectUserName']
    }
    if ([string]::IsNullOrWhiteSpace($targetUser) -or $targetUser -eq '-') { $targetUser = '' }

    $ip = [string]$fields['IpAddress']
    if ($ip -in @('-', '127.0.0.1', '::1', '0.0.0.0', '')) { $ip = '' }

    $eventData = [ordered]@{
        EventID = 4625
        LogName = 'Security'
        TargetUserName = [string]$fields['TargetUserName']
        TargetDomainName = [string]$fields['TargetDomainName']
        SubjectUserName = [string]$fields['SubjectUserName']
        SubjectDomainName = [string]$fields['SubjectDomainName']
        LogonType = [string]$fields['LogonType']
        Status = [string]$fields['Status']
        SubStatus = [string]$fields['SubStatus']
        IpAddress = [string]$fields['IpAddress']
        IpPort = [string]$fields['IpPort']
        WorkstationName = [string]$fields['WorkstationName']
        ProcessName = [string]$fields['ProcessName']
        AuthenticationPackageName = [string]$fields['AuthenticationPackageName']
        FailureReason = [string]$fields['FailureReason']
        RecordId = [long]$Record.RecordId
        Provider = [string]$Record.ProviderName
    }

    return [pscustomobject]@{
        event_id = ('win4625-{0}-{1}' -f $computer, $Record.RecordId)
        event_type = 'windows_failed_login'
        timestamp = $time.ToString('o')
        host = $computer
        username = $targetUser
        source_ip = $ip
        source_integration = 'Windows Security Event Log'
        data_origin = 'LOCAL_WINDOWS'
        event_data = $eventData
    }
}

function Send-Record {
    param([object]$Payload)
    $json = $Payload | ConvertTo-Json -Depth 8 -Compress
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Headers @{
        'X-SentinelX-Key' = $WebhookKey
        'Accept' = 'application/json'
    } -ContentType 'application/json' -Body $json -TimeoutSec 20 | Out-Null
}

do {
    $lastRecordId = 0L
    $hasCheckpoint = Test-Path -LiteralPath $CheckpointPath
    if ($hasCheckpoint) {
        $rawCheckpoint = (Get-Content -LiteralPath $CheckpointPath -Raw).Trim()
        if ($rawCheckpoint -match '^\d+$') { $lastRecordId = [long]$rawCheckpoint }
    }

    $filter = @{ LogName = 'Security'; Id = 4625 }
    if ($hasCheckpoint) {
        $filter['StartTime'] = (Get-Date).AddDays(-7)
    } else {
        $filter['StartTime'] = (Get-Date).AddMinutes(-$InitialLookbackMinutes)
    }

    $records = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
        Where-Object { [long]$_.RecordId -gt $lastRecordId } |
        Sort-Object { [long]$_.RecordId })

    foreach ($record in $records) {
        $payload = Get-EventFields -Record $record
        try {
            Send-Record -Payload $payload
            # Advance only after the intake endpoint accepts the event.
            [System.IO.File]::WriteAllText($CheckpointPath, [string]$record.RecordId)
            Write-Host ('Sent EventID 4625 | Host={0} | User={1} | Record={2}' -f $payload.host, $(if ($payload.username) {$payload.username} else {'(not present)'}), $record.RecordId)
        } catch {
            Write-Warning ('Send failed for Windows record {0}; checkpoint was not advanced. {1}' -f $record.RecordId, $_.Exception.Message)
            break
        }
    }

    if ($Continuous) {
        Start-Sleep -Seconds $IntervalSeconds
    }
} while ($Continuous)
