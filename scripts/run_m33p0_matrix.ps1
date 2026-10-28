param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('ControlledRemaining','Acceptance','Lifecycle','TraceOverhead')]
    [string]$Plan,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9-]{0,31}$')]
    [string]$RunTag=''
)
$ErrorActionPreference='Stop'
$cqRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cqPython=Join-Path $cqRoot 'artifacts\runtime\m33-rc-venv\Scripts\python.exe'
$cqPaths=@('scripts\m32_bootstrap','.','backend','wazuh','scripts') | ForEach-Object {
    (Join-Path $cqRoot $_)
}
$env:PYTHONPATH=$cqPaths -join ';'
$cqTag=if ($RunTag) {"_$RunTag"} else {''}
$cqCells=@()
if ($Plan -eq 'ControlledRemaining') {
    foreach ($cqSize in @(50000,100000)) {
        $cqExperiments=if ($cqSize -eq 100000) {@('E1','E2','E3','E4','E5','E6','E8')} else {@('E1','E2','E3','E4','E5','E8')}
        for ($cqIndex=0;$cqIndex -lt $cqExperiments.Count;$cqIndex++) {
            $cqCells+=,@($cqSize,$cqExperiments[$cqIndex],'durable',$(if ($cqIndex%2) {'AB'} else {'BA'}))
        }
    }
} elseif ($Plan -eq 'Acceptance') {
    foreach ($cqSize in @(10000,50000,100000)) {
        foreach ($cqMode in @('legacy','durable')) {
            foreach ($cqOrder in @('AB','BA')) {$cqCells+=,@($cqSize,'E7',$cqMode,$cqOrder)}
        }
    }
} elseif ($Plan -eq 'Lifecycle') {
    $cqCells+=,@(10000,'E1','durable','ABBA')
    $cqCells+=,@(50000,'E1','durable','BA')
} else {
    $cqCells+=,@(10000,'E7','durable','ABBA')
}
$cqReceipt=Join-Path $cqRoot "artifacts\runtime\m33p0-$Plan$cqTag-exits.json"
if (Test-Path -LiteralPath $cqReceipt) {throw 'Use a new plan receipt; never overwrite earlier attempts'}
$cqResults=@()
Set-Location -LiteralPath $cqRoot
foreach ($cqCell in $cqCells) {
    $cqName="M33P0_${Plan}${cqTag}_$($cqCell[0])_$($cqCell[1])_$($cqCell[2])_$($cqCell[3])"
    $cqOutput="docs/release/$cqName.json"
    $cqLog="artifacts/runtime/$cqName.log"
    if ((Test-Path -LiteralPath $cqOutput) -or (Test-Path -LiteralPath $cqLog)) {throw "Existing evidence: $cqName"}
    $cqArgs=@('scripts/benchmark_m33p0.py','--sizes',"$($cqCell[0])",'--experiments',$cqCell[1],
        '--modes',$cqCell[2],'--order',$cqCell[3],'--output',$cqOutput)
    if ($Plan -eq 'Lifecycle') {$cqArgs+=@('--connection-control','held')}
    if ($Plan -eq 'TraceOverhead') {$cqArgs+=@('--trace-off','--legacy-profiler')}
    $cqStart=[DateTimeOffset]::UtcNow
    Write-Output "START $cqName"
    & $cqPython @cqArgs *> $cqLog
    $cqCode=$LASTEXITCODE
    $cqResults+=@{name=$cqName;native_exit_code=$cqCode;started_at=$cqStart.ToString('o');ended_at=[DateTimeOffset]::UtcNow.ToString('o');output=$cqOutput;log=$cqLog;arguments=$cqArgs}
    [IO.File]::WriteAllText($cqReceipt,($cqResults | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    Write-Output "END $cqName NativeExitCode=$cqCode"
    if ($cqCode -ne 0) {throw "Experiment failed; preserved $cqName, no automatic retries"}
}
