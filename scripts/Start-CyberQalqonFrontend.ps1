[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [int]$Port = 5173,
    [int]$StartupTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$frontend = Join-Path $repository 'frontend'
$runtime = Join-Path $repository 'artifacts\runtime\frontend'
$statusPath = Join-Path $runtime 'status.json'
$stdoutPath = Join-Path $runtime 'frontend.stdout.log'
$stderrPath = Join-Path $runtime 'frontend.stderr.log'
$frontendHealth = "http://127.0.0.1:$Port/health"
$backendHealth = 'http://127.0.0.1:8000/health'

if (-not (Test-Path -LiteralPath (Join-Path $frontend 'package.json') -PathType Leaf)) {
    throw "Frontend package.json was not found below $frontend."
}
if ($Port -lt 1024 -or $Port -gt 65535) {
    throw 'Port must be an unprivileged TCP port between 1024 and 65535.'
}
if ($StartupTimeoutSeconds -lt 5 -or $StartupTimeoutSeconds -gt 120) {
    throw 'StartupTimeoutSeconds must be between 5 and 120.'
}

New-Item -ItemType Directory -Path $runtime -Force | Out-Null

function Test-HttpOk([string]$Uri) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 3
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

if (-not (Test-HttpOk $backendHealth)) {
    throw 'Backend health is not HTTP 200 at the loopback endpoint; frontend startup was not attempted.'
}

if (Test-HttpOk $frontendHealth) {
    $existingListener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') } |
        Select-Object -First 1
    $existing = [ordered]@{
        version = 1
        state = 'ALREADY_HEALTHY'
        frontend_url = "http://127.0.0.1:$Port/"
        backend_health = 200
        frontend_proxy_health = 200
        process_id = if ($existingListener) { $existingListener.OwningProcess } else { $null }
        launcher_process_id = $null
        managed_by_this_invocation = $false
        observed_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $existing | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
    $existing | ConvertTo-Json
    exit 0
}

$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
$arguments = @('run', 'dev', '--', '--host', '127.0.0.1', '--port', "$Port", '--strictPort')
$process = Start-Process -FilePath $npm -ArgumentList $arguments -WorkingDirectory $frontend `
    -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
    -WindowStyle Hidden -PassThru

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($StartupTimeoutSeconds)
do {
    if ($process.HasExited) {
        break
    }
    if (Test-HttpOk $frontendHealth) {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') } |
            Select-Object -First 1
        $ready = [ordered]@{
            version = 1
            state = 'HEALTHY'
            frontend_url = "http://127.0.0.1:$Port/"
            backend_health = 200
            frontend_proxy_health = 200
            process_id = if ($listener) { $listener.OwningProcess } else { $null }
            launcher_process_id = $process.Id
            managed_by_this_invocation = $true
            observed_at = [DateTimeOffset]::UtcNow.ToString('o')
            stdout_log = $stdoutPath
            stderr_log = $stderrPath
        }
        $ready | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
        $ready | ConvertTo-Json
        exit 0
    }
    Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)

if (-not $process.HasExited) {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
}
$failed = [ordered]@{
    version = 1
    state = 'FAILED'
    frontend_url = "http://127.0.0.1:$Port/"
    backend_health = 200
    frontend_proxy_health = $null
    process_id = $process.Id
    launcher_process_id = $process.Id
    managed_by_this_invocation = $true
    observed_at = [DateTimeOffset]::UtcNow.ToString('o')
    stdout_log = $stdoutPath
    stderr_log = $stderrPath
}
$failed | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
throw "Frontend did not become healthy within $StartupTimeoutSeconds seconds. See $stderrPath."
