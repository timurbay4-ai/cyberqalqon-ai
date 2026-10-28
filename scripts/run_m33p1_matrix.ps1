param(
    [Parameter(Mandatory=$true)][ValidateSet('Diagnostics','BuildCost','Acceptance')][string]$Plan,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,31}$')][string]$RunTag,
    [Parameter(Mandatory=$true)][string]$Preflight
)
$ErrorActionPreference='Stop'
$cqRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cqPreflightPath=(Resolve-Path -LiteralPath $Preflight).Path
$cqAdmission=Get-Content -LiteralPath $cqPreflightPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($cqAdmission.admission -ne 'PASS_CONTROLLED_SNAPSHOT_ONLY') {throw 'Controlled idle preflight did not pass'}
$cqAge=([DateTimeOffset]::Now-[DateTimeOffset]::Parse($cqAdmission.clock)).TotalMinutes
if ($cqAge -lt 0 -or $cqAge -gt 10) {throw 'Preflight clock is future/stale; fresh admission required'}
$cqPython=Join-Path $cqRoot 'artifacts/runtime/m33-rc-venv/Scripts/python.exe'
$env:PYTHONUTF8='1'
$env:PYTHONPATH=(@('scripts/m32_bootstrap','.','backend','wazuh','scripts')|ForEach-Object {Join-Path $cqRoot $_}) -join ';'
$cqCells=@()
if ($Plan -eq 'Acceptance') {
    foreach ($cqSize in @(50000,10000,100000)) {
        foreach ($cqMode in @('legacy','durable')) {
            foreach ($cqOrder in @('AB','BA')) {$cqCells+=,@($cqSize,'E7',$cqMode,$cqOrder,'current',$false)}
        }
    }
} elseif ($Plan -eq 'Diagnostics') {
    foreach ($cqMode in @('legacy','durable')) {$cqCells+=,@(50000,'E1',$cqMode,'ABBA','current',$false)}
    foreach ($cqExperiment in @('E2','E3','E4','E5','E7')) {$cqCells+=,@(50000,$cqExperiment,'durable','AB','current',$false)}
    foreach ($cqExperiment in @('E6','E8')) {$cqCells+=,@(100000,$cqExperiment,'durable','BA','current',$false)}
    $cqCells+=,@(50000,'E1','durable','ABBA','current',$true)
} else {
    # A/B/B/A treatment order. All use the actual candidate FTS read path.
    foreach ($cqTreatment in @('old-rebuild','current','current','old-rebuild')) {$cqCells+=,@(50000,'E1','durable','B',$cqTreatment,$false)}
}
$cqReceipt=Join-Path $cqRoot "artifacts/runtime/m33p1-$Plan-$RunTag-exits.json"
if (Test-Path -LiteralPath $cqReceipt) {throw 'Existing receipt; no retry-until-pass'}
$cqFreeze=Join-Path $cqRoot "docs/release/M33P1_${Plan}_${RunTag}_SOURCE_FREEZE.json"
if (Test-Path -LiteralPath $cqFreeze) {throw 'Existing source freeze'}
Set-Location -LiteralPath $cqRoot
$cqHashes=@{}
foreach ($cqFolder in @('backend/app','scripts','experiments')) {
    Get-ChildItem -LiteralPath (Join-Path $cqRoot $cqFolder) -Filter '*.py' -File -Recurse | ForEach-Object {
        $cqRelative=$_.FullName.Substring($cqRoot.Length+1).Replace('\','/')
        $cqHashes[$cqRelative]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
foreach ($cqTool in @('scripts/run_m33p1_matrix.ps1','scripts/m33p1_host_preflight.ps1','backend/requirements.txt','frontend/package-lock.json')) {
    $cqToolPath=Join-Path $cqRoot $cqTool
    if (Test-Path -LiteralPath $cqToolPath) {$cqHashes[$cqTool]=(Get-FileHash -LiteralPath $cqToolPath -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$cqMetadata=@{plan=$Plan;tag=$RunTag;frozen_at=[DateTimeOffset]::UtcNow.ToString('o');cells=$cqCells;
    sources=$cqHashes;preflight=$cqPreflightPath;preflight_sha256=(Get-FileHash -LiteralPath $cqPreflightPath -Algorithm SHA256).Hash.ToLowerInvariant();
    threshold=1.25;original_workload='UNCHANGED_M31_MEASURE_E7';production='NOT_AUTHORIZED'}
[IO.File]::WriteAllText($cqFreeze,($cqMetadata|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
$cqResults=@();$cqIndex=0
foreach ($cqCell in $cqCells) {
    $cqName="M33P1_${Plan}_${RunTag}_$cqIndex-$($cqCell[0])-$($cqCell[1])-$($cqCell[2])-$($cqCell[3])"
    $cqOutput="docs/release/$cqName.json";$cqLog="artifacts/runtime/$cqName.log"
    if ((Test-Path -LiteralPath $cqOutput) -or (Test-Path -LiteralPath $cqLog)) {throw 'Existing evidence path'}
    $cqArguments=@('scripts/benchmark_m33p1.py','--sizes',"$($cqCell[0])",'--experiments',$cqCell[1],
        '--modes',$cqCell[2],'--order',$cqCell[3],'--build-treatment',$cqCell[4],'--output',$cqOutput)
    if ($Plan -eq 'Diagnostics') {$cqArguments+=@('--native-probe')}
    if ($cqCell[5]) {$cqArguments+=@('--reuse-e1')}
    $cqStart=[DateTimeOffset]::UtcNow
    Write-Output "START $cqName"
    & $cqPython @cqArguments *> $cqLog
    $cqCode=$LASTEXITCODE
    $cqResults+=@{name=$cqName;native_exit_code=$cqCode;arguments=$cqArguments;output=$cqOutput;log=$cqLog;
        started_at=$cqStart.ToString('o');ended_at=[DateTimeOffset]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText($cqReceipt,($cqResults|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    Write-Output "END $cqName NativeExitCode=$cqCode"
    if ($cqCode -ne 0) {throw 'Stopped on failure; partial evidence preserved, no automatic retry'}
    foreach ($cqNameToCheck in $cqHashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $cqRoot $cqNameToCheck) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $cqHashes[$cqNameToCheck]) {
            throw 'Source changed during frozen cohort; stop and retain evidence'
        }
    }
    $cqIndex++
}
