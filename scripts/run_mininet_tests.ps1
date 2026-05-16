param(
    [string]$Distro = "Ubuntu-22.04",
    [switch]$FullFatTree,
    [switch]$E2E,
    [int]$Duration = 60,
    [int]$E2EK = 2
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslRepo = $repo -replace "\\", "/"
$wslRepo = $wslRepo -replace "^([A-Za-z]):", '/mnt/$1'
$wslRepo = $wslRepo.ToLower()

$argsList = @()
if ($FullFatTree) { $argsList += "--full-fat-tree" }
if ($E2E) {
    $argsList += "--e2e"
    $argsList += "--e2e-k"
    $argsList += "$E2EK"
    $argsList += "--duration"
    $argsList += "$Duration"
}

$joined = ($argsList -join " ")
$cmd = "cd '$wslRepo'; sudo bash scripts/run_mininet_tests.sh $joined"

Write-Host "Running in WSL distro: $Distro"
Write-Host $cmd
wsl.exe -d $Distro -- bash -lc $cmd
