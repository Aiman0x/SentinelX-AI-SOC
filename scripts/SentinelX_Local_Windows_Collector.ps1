# SentinelX read-only Windows Security + Sysmon event collector
# Sends selected security telemetry over outbound HTTPS. It never changes endpoint settings.
[CmdletBinding()]
param(
    [switch]$Continuous,
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 30,
    [ValidateRange(1, 1440)][int]$InitialLookbackMinutes = 15
)

$ErrorActionPreference = 'Stop'
$CollectorApiUrl = $env:SENTINELX_COLLECTOR_API_URL
$CollectorToken = $env:SENTINELX_COLLECTOR_TOKEN
if ([string]::IsNullOrWhiteSpace($CollectorApiUrl) -or [string]::IsNullOrWhiteSpace($CollectorToken)) {
    throw 'Set SENTINELX_COLLECTOR_API_URL and SENTINELX_COLLECTOR_TOKEN before running the collector.'
}
if ($CollectorApiUrl -notmatch '^https://') { throw 'SENTINELX_COLLECTOR_API_URL must use HTTPS.' }
if ($CollectorToken.Length -lt 40 -or $CollectorToken.Length -gt 256) { throw 'Collector token length is invalid.' }

$CollectorEventsUrl = $CollectorApiUrl.TrimEnd('/') + '/api/collector/events'
$CollectorConfigUrl = $CollectorApiUrl.TrimEnd('/') + '/api/collector/config'
$CollectorStopUrl = $CollectorApiUrl.TrimEnd('/') + '/api/collector/stop'
$StateDirectory = Join-Path $env:LOCALAPPDATA 'SentinelX'
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null

function Test-CollectorPaused {
    $config = Invoke-RestMethod -Uri $CollectorConfigUrl -Method Get -Headers @{ Authorization = "Bearer $CollectorToken"; Accept = 'application/json' } -TimeoutSec 10
    return [bool]$config.paused
}

function Get-EventType {
    param([string]$Channel, [int]$EventId)
    if ($Channel -eq 'Security') {
        switch ($EventId) {
            4624 { return 'windows_successful_login' }
            4625 { return 'windows_failed_login' }
            4688 { return 'windows_process_created' }
            4697 { return 'windows_service_installed' }
            4720 { return 'windows_user_created' }
            { $_ -in 4728, 4732 } { return 'windows_group_member_added' }
            1102 { return 'windows_audit_log_cleared' }
        }
    } else {
        switch ($EventId) {
            1  { return 'sysmon_process_created' }
            3  { return 'sysmon_network_connection' }
            7  { return 'sysmon_image_loaded' }
            10 { return 'sysmon_process_access' }
            11 { return 'sysmon_file_created' }
            12 { return 'sysmon_registry_object_created' }
            13 { return 'sysmon_registry_value_set' }
            22 { return 'sysmon_dns_query' }
            23 { return 'sysmon_file_deleted' }
            26 { return 'sysmon_file_delete_detected' }
        }
    }
    return 'windows_security_event'
}

function Get-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record, [string]$Channel)
    [xml]$xml = $Record.ToXml()
    $fields = @{}
    foreach ($node in @($xml.Event.EventData.Data)) {
        if ($null -ne $node -and -not [string]::IsNullOrWhiteSpace([string]$node.Name)) {
            $fields[[string]$node.Name] = [string]$node.InnerText
        }
    }

    $system = $xml.Event.System
    $eventId = [int]$Record.Id
    $time = [DateTime]::Parse([string]$system.TimeCreated.SystemTime).ToUniversalTime()
    $computer = [string]$system.Computer
    if ([string]::IsNullOrWhiteSpace($computer)) { $computer = $env:COMPUTERNAME }

    $username = [string]$fields['TargetUserName']
    if ([string]::IsNullOrWhiteSpace($username) -or $username -eq '-') { $username = [string]$fields['SubjectUserName'] }
    if ([string]::IsNullOrWhiteSpace($username) -or $username -eq '-') { $username = [string]$fields['User'] }
    if ($username -eq '-') { $username = '' }

    $sourceIp = [string]$fields['IpAddress']
    if ([string]::IsNullOrWhiteSpace($sourceIp) -or $sourceIp -in @('-', '127.0.0.1', '::1', '0.0.0.0')) {
        $sourceIp = [string]$fields['SourceIp']
    }
    $destinationIp = [string]$fields['DestinationIp']
    $eventType = Get-EventType -Channel $Channel -EventId $eventId
    $severity = 'info'
    if ($eventId -in @(4625, 4720, 4728, 4732)) { $severity = 'medium' }
    if ($eventId -in @(4697, 1102)) { $severity = 'high' }

    $eventData = [ordered]@{}
    foreach ($key in $fields.Keys) { $eventData[$key] = [string]$fields[$key] }
    $eventData['EventID'] = $eventId
    $eventData['Channel'] = $Channel
    $eventData['RecordId'] = [long]$Record.RecordId
    $eventData['Provider'] = [string]$Record.ProviderName

    $detailText = (($fields.GetEnumerator() | Select-Object -First 18 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
    $message = "$eventType | $detailText"
    return [pscustomobject]@{
        eventId = ('win-{0}-{1}-{2}' -f $Channel.ToLower().Replace('/', '-'), $computer, $Record.RecordId)
        eventType = $eventType
        observedAt = $time.ToString('o')
        host = $computer
        username = $username
        sourceIp = $sourceIp
        destinationIp = $destinationIp
        severity = $severity
        message = $message
        sourceIntegration = $Channel
        dataOrigin = 'LOCAL_WINDOWS'
        eventData = $eventData
    }
}

function Send-Record {
    param([object]$Payload, [string]$IntegrationId)
    $body = @{
        integrationId = $IntegrationId
        events = @($Payload)
    } | ConvertTo-Json -Depth 12 -Compress
    $response = Invoke-RestMethod -Uri $CollectorEventsUrl -Method Post -Headers @{
        Authorization = "Bearer $CollectorToken"
        Accept = 'application/json'
    } -ContentType 'application/json' -Body $body -TimeoutSec 20
    if ($null -eq $response -or [int]$response.accepted -lt 1) {
        throw 'SentinelX intake did not confirm event acceptance.'
    }
}

function Invoke-ChannelCollection {
    param([string]$Channel, [int[]]$EventIds, [string]$IntegrationId)
    $checkpointPath = Join-Path $StateDirectory ("last-" + $IntegrationId + "-record-id.txt")
    $lastRecordId = 0L
    $hasCheckpoint = Test-Path -LiteralPath $checkpointPath
    if ($hasCheckpoint) {
        $rawCheckpoint = (Get-Content -LiteralPath $checkpointPath -Raw).Trim()
        if ($rawCheckpoint -match '^\d+$') { $lastRecordId = [long]$rawCheckpoint }
    }

    $filter = @{ LogName = $Channel; Id = $EventIds }
    $filter['StartTime'] = if ($hasCheckpoint) { (Get-Date).AddDays(-7) } else { (Get-Date).AddMinutes(-$InitialLookbackMinutes) }
    $records = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
        Where-Object { [long]$_.RecordId -gt $lastRecordId } |
        Sort-Object { [long]$_.RecordId })

    foreach ($record in $records) {
        $payload = Get-EventFields -Record $record -Channel $Channel
        try {
            Send-Record -Payload $payload -IntegrationId $IntegrationId
            # Advance the channel-specific checkpoint only after the gateway accepts the event.
            [System.IO.File]::WriteAllText($checkpointPath, [string]$record.RecordId)
            Write-Host ('Sent {0} EventID {1} | Host={2} | Record={3}' -f $Channel, $record.Id, $payload.host, $record.RecordId)
        } catch {
            Write-Warning ('Send failed for {0} record {1}; checkpoint was not advanced. {2}' -f $Channel, $record.RecordId, $_.Exception.Message)
            break
        }
    }
}

try {
    do {
        try {
            if (Test-CollectorPaused) {
                Write-Host 'Collector is paused by SentinelX; no Windows events will be sent.'
            } else {
                Invoke-ChannelCollection -Channel 'Security' -EventIds @(4624,4625,4688,4697,4720,4728,4732,1102) -IntegrationId 'windows_security'
                try {
                    Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop | Out-Null
                    Invoke-ChannelCollection -Channel 'Microsoft-Windows-Sysmon/Operational' -EventIds @(1,3,7,10,11,12,13,22,23,26) -IntegrationId 'sysmon'
                } catch {
                    Write-Host 'Sysmon channel not available; Security events will continue to be collected.'
                }
            }
        } catch {
            Write-Warning ('Collector cycle failed: ' + $_.Exception.Message)
        }
        if ($Continuous) { Start-Sleep -Seconds $IntervalSeconds }
    } while ($Continuous)
} finally {
    # Ctrl+C / normal shutdown removes this enrollment. A fresh run needs a fresh token.
    if ($Continuous) {
        try {
            Invoke-RestMethod -Uri $CollectorStopUrl -Method Post -Headers @{
                Authorization = "Bearer $CollectorToken"
                Accept = 'application/json'
            } -ContentType 'application/json' -Body '{}' -TimeoutSec 10 | Out-Null
            Write-Host 'SentinelX host enrollment removed. Enroll again to start a fresh session.'
        } catch {
            Write-Warning 'Could not notify SentinelX that the collector stopped. Remove this host from the dashboard if it remains listed.'
        }
    }
}
