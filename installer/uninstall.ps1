<#
.SYNOPSIS
  Removes Android Guardian from this Windows user account. Reverses every step of install.ps1.

.DESCRIPTION
  Run it from any of:
    Settings > Apps > Installed apps > Android Guardian > Uninstall
    Uninstall.cmd in the program folder
    powershell -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\AndroidGuardian\uninstall.ps1" [-Quiet]

  Removes: the program folder, the Desktop and Start Menu shortcuts, and the entry in Installed apps.
  Saved reports are moved to a folder on your Desktop first, unless you answer "n" to the question.
  Nothing is touched on the phone.

  It always removes the INSTALLED copy (the folder recorded in Installed apps), wherever this file is run
  from. A portable copy is removed by deleting its folder.

.PARAMETER Quiet
  No questions and no "press Enter" (used by QuietUninstallString, winget and CI). Reports are kept.

.NOTES
  Exit codes:
    0  removed, or nothing was installed
    1  unexpected error
    5  some files could not be removed (in use, or access denied); the message lists them
    6  reports could not be saved, so nothing was deleted

  How it removes its own folder: it copies itself to %TEMP%, moves its working directory out of the
  program folder, runs the copy in the same window and waits, then deletes the copy.
  ASCII only on purpose (Windows PowerShell 5.1 reads a .ps1 without a BOM as ANSI).
#>
[CmdletBinding()]
param(
  [switch]$Quiet,
  [string]$Target       # internal: set by the first stage when it re-runs this file from %TEMP%
)
$ErrorActionPreference = 'Stop'
$AppName = 'Android Guardian'
$RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AndroidGuardian'
$WinPS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Ok([string]$t) { Write-Host '  [ok] ' -ForegroundColor Green -NoNewline; Write-Host $t }
function Warn([string]$t) { Write-Host '  [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Test-Under([string]$path, [string]$dir) {
  $p = $path.TrimEnd('\') + '\'; $d = $dir.TrimEnd('\') + '\'
  return $p.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)
}
# Can we ask questions? Not with -Quiet, not without a console, not with redirected input.
$Interactive = (-not $Quiet) -and [Environment]::UserInteractive
try { if ([Console]::IsInputRedirected) { $Interactive = $false } } catch { $Interactive = $false }
function Pause-End { if ($Interactive) { try { Write-Host ''; Read-Host '  Press Enter to close this window' | Out-Null } catch { } } }

# ------------------------------------------------------------------ stage 1: relaunch from %TEMP%
if (-not $Target) {
  $installed = (Get-ItemProperty -Path $RegKey -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation
  $dest = if ($installed) { $installed } else { Join-Path $env:LOCALAPPDATA 'Programs\AndroidGuardian' }
  $dest = $dest.TrimEnd('\')

  # Step out of the program folder: a process whose current directory is inside it keeps it locked.
  Set-Location -LiteralPath $env:TEMP
  [Environment]::CurrentDirectory = $env:TEMP
  # Tidy copies left behind by an interrupted earlier run.
  Get-ChildItem -LiteralPath $env:TEMP -Filter 'AndroidGuardian-uninstall-*.ps1' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } | Remove-Item -Force -ErrorAction SilentlyContinue

  $copy = Join-Path $env:TEMP ('AndroidGuardian-uninstall-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
  Copy-Item -LiteralPath $PSCommandPath -Destination $copy -Force
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $copy, '-Target', $dest)
  if ($Quiet) { $a += '-Quiet' }
  # Same window (so the question stays visible), wait for it, pass its exit code on.
  & $WinPS @a
  $code = $LASTEXITCODE
  Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
  exit $code
}

# ------------------------------------------------------------------ stage 2: the actual removal
$Dest = $Target.TrimEnd('\')
try { $Host.UI.RawUI.WindowTitle = "$AppName uninstall" } catch { }
Write-Host ''
Write-Host "  Removing $AppName" -ForegroundColor Cyan
Write-Host "  from $Dest" -ForegroundColor DarkGray
Write-Host ''

try {
  # Only ever delete a folder that is recognisably ours.
  $ours = ((Split-Path -Leaf $Dest) -eq 'AndroidGuardian') -and (
    (Test-Path -LiteralPath (Join-Path $Dest 'AndroidGuardian.exe')) -or
    (Test-Path -LiteralPath (Join-Path $Dest 'uninstall.ps1')) -or
    (Test-Path -LiteralPath (Join-Path $Dest 'VERSION')))
  $present = Test-Path -LiteralPath $Dest
  if ($present -and -not $ours) { Warn "$Dest does not look like an Android Guardian folder, so it is left alone." }

  # Close the app and the adb server it started (adb.exe keeps platform-tools locked).
  $procs = @(Get-Process -Name AndroidGuardian, adb, aapt2 -ErrorAction SilentlyContinue | Where-Object {
    $p = $null; try { $p = $_.Path } catch { }
    ($p -and (Test-Under $p $Dest)) -or (-not $p -and $_.ProcessName -eq 'AndroidGuardian')
  })
  if ($procs.Count) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    $procs | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Ok "Closed the running $AppName"
  }

  # Reports are evidence: keep them unless the user explicitly says no.
  $reports = Join-Path $Dest 'reports'
  if ($present -and $ours -and (Test-Path -LiteralPath $reports) -and
      @(Get-ChildItem -LiteralPath $reports -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
    $keep = $true
    if ($Interactive) {
      Write-Host '  You have saved scan reports. If someone may be spying on you, they are evidence.' -ForegroundColor Yellow
      try {
        $answer = Read-Host '  Keep them? They will be moved to a folder on your Desktop. [Y/n]'
        if ($answer -match '^\s*(n|no)\s*$') { $keep = $false }
      } catch { $keep = $true }
    }
    if ($keep) {
      $base = [Environment]::GetFolderPath('Desktop')
      if (-not $base) { $base = [Environment]::GetFolderPath('MyDocuments') }
      $out = Join-Path $base 'Android Guardian reports'
      try {
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Copy-Item -Path (Join-Path $reports '*') -Destination $out -Recurse -Force
        $want = @(Get-ChildItem -LiteralPath $reports -Recurse -File).Count
        $got = @(Get-ChildItem -LiteralPath $out -Recurse -File).Count
        if ($got -lt $want) { throw "only $got of $want files arrived" }
      } catch {
        Write-Host "  Could not save your reports to $out ($($_.Exception.Message))." -ForegroundColor Red
        Write-Host "  Nothing was deleted. Copy $reports somewhere safe, then run the uninstaller again." -ForegroundColor Red
        Pause-End
        exit 6
      }
      Ok "Reports saved in $out"
    } else { Ok 'Reports will be deleted' }
  }

  foreach ($folder in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
    if (-not $folder) { continue }
    $lnk = Join-Path $folder "$AppName.lnk"
    if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force; Ok "Removed shortcut $lnk" }
  }

  if (Test-Path $RegKey) { Remove-Item $RegKey -Recurse -Force; Ok 'Removed the entry in Installed apps' }

  $failed = $false
  if ($present -and $ours) {
    # Antivirus or the search indexer can hold a file for a moment: retry a few times.
    for ($i = 1; $i -le 5; $i++) {
      try { Remove-Item -LiteralPath $Dest -Recurse -Force; break }
      catch { if ($i -eq 5) { $failed = $true } else { Start-Sleep -Seconds $i } }
    }
    if ($failed -or (Test-Path -LiteralPath $Dest)) {
      $failed = $true
      $left = @(Get-ChildItem -LiteralPath $Dest -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 5 -ExpandProperty FullName)
      Write-Host "  Some files could not be removed from $Dest (in use?):" -ForegroundColor Red
      foreach ($l in $left) { Write-Host "    $l" -ForegroundColor Red }
      Write-Host '  Restart Windows and delete that folder by hand. Everything else is already removed.' -ForegroundColor Red
    } else { Ok "Removed $Dest" }
  } elseif (-not $present) { Ok 'Program folder was already gone' }

  Write-Host ''
  if (-not $failed) {
    Write-Host "  $AppName has been removed. Nothing was changed on your phone." -ForegroundColor Green
  }
  Write-Host '  If USB debugging is still on: phone Settings > Developer options > USB debugging > off.'
  Pause-End
  if ($failed) { exit 5 }
  exit 0
} catch {
  Write-Host ''
  Write-Host "  Uninstall did not finish: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "  ($($_.InvocationInfo.PositionMessage -replace '\s+', ' '))" -ForegroundColor DarkGray
  Pause-End
  exit 1
}
