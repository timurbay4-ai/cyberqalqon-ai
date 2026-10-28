param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $Output) {throw 'New evidence path required'}
$cqOs=Get-CimInstance Win32_OperatingSystem
$cqProcessor=Get-CimInstance Win32_Processor
$cqLogicalDisk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$cqSamples=@()
for ($cqIndex=0;$cqIndex -lt 3;$cqIndex++) {
    if ($cqIndex -gt 0) {Start-Sleep -Seconds 2}
    $cqMemory=Get-CimInstance Win32_OperatingSystem
    $cqCpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
    $cqDisk=Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
    $cqSamples+=@{at=[DateTimeOffset]::Now.ToString('o');available_ram_bytes=([long]$cqMemory.FreePhysicalMemory*1024);
        cpu_percent=$cqCpu.PercentProcessorTime;disk_queue=$cqDisk.CurrentDiskQueueLength;
        disk_read_bytes_per_second=$cqDisk.DiskReadBytesPersec;disk_write_bytes_per_second=$cqDisk.DiskWriteBytesPersec}
}
$cqPass=($cqLogicalDisk.FreeSpace -ge 10GB)
foreach ($cqSample in $cqSamples) {
    if ($null -eq $cqSample.cpu_percent -or $null -eq $cqSample.disk_queue -or
        $cqSample.available_ram_bytes -lt 1GB -or $cqSample.cpu_percent -gt 25 -or $cqSample.disk_queue -gt 1) {$cqPass=$false}
}
$cqReport=@{scope='READ_ONLY_USER_LEVEL_AGGREGATES_NO_PROCESS_ENUMERATION';clock=[DateTimeOffset]::Now.ToString('o');
    windows=@{version=$cqOs.Version;build=$cqOs.BuildNumber;caption=$cqOs.Caption};
    cpu_model=@($cqProcessor.Name);logical_processors=@($cqProcessor.NumberOfLogicalProcessors);
    filesystem=$cqLogicalDisk.FileSystem;free_disk_bytes=$cqLogicalDisk.FreeSpace;
    samples=$cqSamples;admission=if($cqPass){'PASS_CONTROLLED_SNAPSHOT_ONLY'}else{'OPERATOR_ACTION_REQUIRED_CONTROLLED_IDLE_HOST_BENCHMARK'};
    power_scheme=@(powercfg.exe /GETACTIVESCHEME);power_source='NOT_OBSERVED';disk_type='NOT_OBSERVED';
    limits=@{minimum_available_ram_bytes=1GB;maximum_cpu_percent=25;maximum_disk_queue=1;minimum_free_disk_bytes=10GB};
    application_shutdown='NOT_PERFORMED';security_or_power_change='NOT_PERFORMED';privileged_diagnostics='NOT_PERFORMED'}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Output),($cqReport|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
Write-Output ($cqReport|ConvertTo-Json -Depth 12)
if (-not $cqPass) {exit 2}
