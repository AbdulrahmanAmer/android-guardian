<#
.SYNOPSIS
  Removes Android Guardian from this Windows user account. Reverses every step of install.ps1.

.DESCRIPTION
  Run from Settings > Apps > Installed apps > Android Guardian > Uninstall, or Uninstall.cmd, or:
      powershell -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\AndroidGuardian\uninstall.ps1"

  Removes: the program folder, the Desktop and Start Menu shortcuts, and the entry in Installed apps.
  Asks first whether to keep your saved reports (moved to the Desktop). Nothing is touched on the phone.
#>
[CmdletBinding()]
param(
  [switch]$Quiet,       # no questions: reports are kept on the Desktop
  [string]$Target       # internal: folder to remove when running from the temp copy
)
$ErrorActionPreference = 'Stop'
$AppName = 'Android Guardian'
$RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AndroidGuardian'

$self = $MyInvocation.MyCommand.Path
$Dest = if ($Target) { $Target } else { Split-Path -Parent $self }

# A script cannot delete the folder it is running from: re-launch a copy of itself from %TEMP%.
if (-not $Target) {
  $copy = Join-Path $env:TEMP ("AndroidGuardian-uninstall-" + [guid]::NewGuid().ToString('N') + '.ps1')
  Copy-Item $self $copy -Force
  $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$copy`"", '-Target', "`"$Dest`"")
  if ($Quiet) { $args += '-Quiet' }
  Start-Process powershell.exe -ArgumentList $args -Wait
  exit 0
}

Write-Host ""
Write-Host "Removing $AppName from $Dest" -ForegroundColor Cyan

Get-Process -Name AndroidGuardian -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Reports: keep them unless the user says otherwise.
$reports = Join-Path $Dest 'reports'
if (Test-Path $reports) {
  $hasReports = (Get-ChildItem $reports -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
  if ($hasReports) {
    $keep = $true
    if (-not $Quiet) {
      $answer = Read-Host "Keep your saved scan reports? They will be moved to your Desktop. [Y/n]"
      if ($answer -match '^(n|no)$') { $keep = $false }
    }
    if ($keep) {
      $out = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Android Guardian reports'
      New-Item -ItemType Directory -Path $out -Force | Out-Null
      Copy-Item (Join-Path $reports '*') $out -Recurse -Force
      Write-Host "  - Reports moved to $out"
    }
  }
}

foreach ($lnk in @(
  (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"),
  (Join-Path ([Environment]::GetFolderPath('Programs')) "$AppName.lnk")
)) { if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "  - Removed shortcut $lnk" } }

if (Test-Path $RegKey) { Remove-Item $RegKey -Recurse -Force; Write-Host "  - Removed the entry in Installed apps" }

if (Test-Path $Dest) {
  Remove-Item $Dest -Recurse -Force
  Write-Host "  - Removed $Dest"
}

Write-Host ""
Write-Host "$AppName has been removed. Nothing was changed on your phone." -ForegroundColor Green
Write-Host "If you still have USB debugging on, turn it off: Settings > Developer options > USB debugging."
if (-not $Quiet) { Write-Host ""; Read-Host "Press Enter to close" | Out-Null }
Remove-Item $self -Force -ErrorAction SilentlyContinue
