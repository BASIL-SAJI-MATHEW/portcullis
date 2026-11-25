# Portcullis installer for Windows.
#   .\install.ps1            install and start in observe mode (blocks nothing)
#   .\install.ps1 -Enforce   install and start blocking attackers right away
# Read this file before you run it. It only touches C:\ProgramData\Portcullis and one scheduled task.
#Requires -RunAsAdministrator
param([switch]$Enforce)

$ErrorActionPreference = "Stop"
$Source = "https://github.com/BASIL-SAJI-MATHEW/portcullis/archive/refs/heads/main.zip"
$Root = Join-Path $env:ProgramData "Portcullis"
$Conf = Join-Path $Root "portcullis.toml"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Find Python 3.11 or newer.
$pyExe = $null
$pyArgs = @()
foreach ($candidate in @("py", "python", "python3")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $try = if ($candidate -eq "py") { @("-3") } else { @() }
    & $cmd.Source @try -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $pyExe = $cmd.Source; $pyArgs = $try; break }
}
if (-not $pyExe) { throw "Python 3.11 or newer is required. Install it from https://www.python.org/downloads/ and run this again." }

Write-Host "Installing Portcullis into $Root ..."
New-Item -ItemType Directory -Force -Path $Root | Out-Null
& $pyExe @pyArgs -m venv (Join-Path $Root "venv")
$venvPython = Join-Path $Root "venv\Scripts\python.exe"
& $venvPython -m pip install --quiet --upgrade $Source
$exe = Join-Path $Root "venv\Scripts\portcullis.exe"

if (-not (Test-Path $Conf)) {
    & $exe init --path $Conf | Out-Null
    $db = (Join-Path $Root "portcullis.db") -replace "\\", "/"
    $text = [System.IO.File]::ReadAllText($Conf)
    $text = $text -replace '(?m)^path = "portcullis\.db"', ('path = "' + $db + '"')
    [System.IO.File]::WriteAllText($Conf, $text, $Utf8NoBom)
}
if ($Enforce) {
    $text = [System.IO.File]::ReadAllText($Conf)
    $text = $text -replace '(?m)^dry_run = true', 'dry_run = false'
    [System.IO.File]::WriteAllText($Conf, $text, $Utf8NoBom)
}
& $exe check -c $Conf

# Run at startup as SYSTEM (needed to read the Security log and edit the firewall).
$action = New-ScheduledTaskAction -Execute $exe -Argument ("run -c `"" + $Conf + "`"") -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName "Portcullis" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "Portcullis"

Write-Host ""
Write-Host "Portcullis is running. Dashboard: http://127.0.0.1:8787"
if ($Enforce) {
    Write-Host "Blocking is ON."
} else {
    Write-Host "Observe mode: nothing is blocked yet. When you are happy, set dry_run = false in $Conf"
    Write-Host "and restart the task:  Stop-ScheduledTask Portcullis; Start-ScheduledTask Portcullis"
}
