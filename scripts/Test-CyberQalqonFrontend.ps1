[CmdletBinding()]
param(
    [int]$Port = 5173
)

$ErrorActionPreference = 'Stop'

function Get-HttpStatus([string]$Uri) {
    try {
        return (Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 5).StatusCode
    }
    catch {
        return $null
    }
}

$backendStatus = Get-HttpStatus 'http://127.0.0.1:8000/health'
$frontendStatus = Get-HttpStatus "http://127.0.0.1:$Port/"
$proxyStatus = Get-HttpStatus "http://127.0.0.1:$Port/health"
$listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') } |
    Select-Object -First 1

$healthy = $backendStatus -eq 200 -and $frontendStatus -eq 200 -and $proxyStatus -eq 200
$result = [ordered]@{
    version = 1
    state = if ($healthy) { 'HEALTHY' } else { 'UNAVAILABLE' }
    backend_health = $backendStatus
    frontend_health = $frontendStatus
    frontend_proxy_health = $proxyStatus
    loopback_listener = $null -ne $listener
    listener_process_id = if ($listener) { $listener.OwningProcess } else { $null }
    browser_uat = 'DEFERRED_BY_USER'
    observed_at = [DateTimeOffset]::UtcNow.ToString('o')
}
$result | ConvertTo-Json
if (-not $healthy) {
    exit 1
}
