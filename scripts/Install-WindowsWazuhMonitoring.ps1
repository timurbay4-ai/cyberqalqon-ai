[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ManagerAddress = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$ManagerPort = 2514,
    [ValidateRange(1, 65535)][int]$EnrollmentPort = 2515,
    [string]$AgentName = "cyberqalqon-windows-$env:COMPUTERNAME",
    [switch]$Enroll,
    [string]$AgentRoot = 'C:\Program Files (x86)\ossec-agent'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PrivateOrLoopbackAddress([string]$Value) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)) { return $false }
    if ([System.Net.IPAddress]::IsLoopback($parsed)) { return $true }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $bytes = $parsed.GetAddressBytes()
    return $bytes[0] -eq 10 -or `
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or `
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session. No changes were made.'
}
if (-not (Test-PrivateOrLoopbackAddress $ManagerAddress)) {
    throw 'ManagerAddress must be a loopback or RFC1918 address.'
}
if ($AgentName -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
    throw 'AgentName must contain only letters, numbers, dot, underscore, or hyphen.'
}

$configPath = Join-Path $AgentRoot 'ossec.conf'
$keyPath = Join-Path $AgentRoot 'client.keys'
$agentAuthPath = Join-Path $AgentRoot 'agent-auth.exe'
if (-not (Test-Path -LiteralPath $configPath)) { throw "Missing Wazuh configuration: $configPath" }
if (-not (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue)) { throw 'WazuhSvc is not installed.' }

$timestamp = Get-Date -Format 'yyyyMMddTHHmmss'
$backupDirectory = Join-Path $env:ProgramData "CyberQalqon\backups\windows-agent-$timestamp"
if ($PSCmdlet.ShouldProcess($configPath, 'Back up and apply bounded Windows Event Channel monitoring')) {
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $backupDirectory 'ossec.conf')
    if (Test-Path -LiteralPath $keyPath) {
        Copy-Item -LiteralPath $keyPath -Destination (Join-Path $backupDirectory 'client.keys')
    }
    & icacls.exe $backupDirectory /inheritance:r | Out-Null
    & icacls.exe $backupDirectory /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

    [xml]$document = Get-Content -LiteralPath $configPath -Raw
    $client = $document.ossec_config.client
    $client.server.address = $ManagerAddress
    $client.server.port = [string]$ManagerPort
    $client.server.protocol = 'tcp'
    $client.enrollment.enabled = 'yes'
    $client.enrollment.agent_name = $AgentName

    $monitoredLocations = @(
        'Application', 'Security', 'System',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    )
    @($document.ossec_config.localfile) | Where-Object {
        $_.location -and $monitoredLocations -contains [string]$_.location
    } | ForEach-Object { [void]$document.ossec_config.RemoveChild($_) }

    $definitions = @(
        @('Security', 'Event/System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=1102)]'),
        @('System', "Event/System[Provider[@Name='Service Control Manager'] and EventID=7045]"),
        @('Microsoft-Windows-PowerShell/Operational', 'Event/System[(EventID=4103 or EventID=4104)]'),
        @('Microsoft-Windows-Windows Defender/Operational', 'Event/System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5000 or EventID=5001 or EventID=5004 or EventID=5007)]')
    )
    foreach ($definition in $definitions) {
        $localfile = $document.CreateElement('localfile')
        $location = $document.CreateElement('location')
        $location.InnerText = $definition[0]
        $format = $document.CreateElement('log_format')
        $format.InnerText = 'eventchannel'
        $query = $document.CreateElement('query')
        $query.InnerText = $definition[1]
        [void]$localfile.AppendChild($location)
        [void]$localfile.AppendChild($format)
        [void]$localfile.AppendChild($query)
        [void]$document.ossec_config.AppendChild($localfile)
    }

    $temporaryPath = Join-Path $backupDirectory 'ossec.conf.new'
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create($temporaryPath, $settings)
    try { $document.Save($writer) } finally { $writer.Dispose() }
    [xml](Get-Content -LiteralPath $temporaryPath -Raw) | Out-Null
    Copy-Item -LiteralPath $temporaryPath -Destination $configPath -Force

    if ($Enroll) {
        if (-not (Test-Path -LiteralPath $agentAuthPath)) { throw 'agent-auth.exe is unavailable.' }
        if (-not (Test-NetConnection -ComputerName $ManagerAddress -Port $EnrollmentPort -InformationLevel Quiet)) {
            throw "Enrollment endpoint $ManagerAddress`:$EnrollmentPort is unreachable. Configuration was backed up at $backupDirectory."
        }
        & $agentAuthPath -m $ManagerAddress -p $EnrollmentPort -A $AgentName
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $keyPath) -or (Get-Item $keyPath).Length -eq 0) {
            throw 'Supported Wazuh enrollment did not produce a client key.'
        }
    }

    Restart-Service -Name WazuhSvc
    if ((Get-Service -Name WazuhSvc).Status -ne 'Running') { throw 'WazuhSvc did not restart.' }
    Write-Output "Windows Wazuh monitoring configured. Backup: $backupDirectory"
}
