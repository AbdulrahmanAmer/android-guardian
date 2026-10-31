<#
.SYNOPSIS
  Installs Android Guardian for the current Windows user. No administrator rights needed.

.DESCRIPTION
  One line, from PowerShell:
      irm https://raw.githubusercontent.com/AbdulrahmanAmer/android-guardian/main/installer/install.ps1 | iex
  Or from an unzipped release folder:   Install.cmd

  What it does, exactly:
    1. Downloads the latest release zip from GitHub (or uses -Local <folder>).
    2. Copies it to  %LOCALAPPDATA%\Programs\AndroidGuardian  (your settings and reports are kept on upgrade).
    3. Removes the "downloaded from the internet" mark from the files, so Windows SmartScreen does not warn.
    4. Creates shortcuts on the Desktop and in the Start Menu.
    5. Registers "Android Guardian" in Settings > Apps > Installed apps, with a working Uninstall button.
  Nothing is written anywhere else. uninstall.ps1 reverses every step.
#>
[CmdletBinding()]
param(
  [string]$Local,              # install from an already-unzipped folder instead of downloading
  [string]$Repo = 'AbdulrahmanAmer/android-guardian',
  [switch]$NoShortcuts,
  [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AppName = 'Android Guardian'
$Dest = Join-Path $env:LOCALAPPDATA 'Programs\AndroidGuardian'
$RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AndroidGuardian'

function Step($text) { Write-Host "  - $text" }
Write-Host ""
Write-Host "Installing $AppName" -ForegroundColor Cyan
Write-Host "  into $Dest"
Write-Host ""

# 0. Close a running copy so files can be replaced.
Get-Process -Name AndroidGuardian -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 1. Get the files.
$tmp = $null
if ($Local) {
  $src = (Resolve-Path $Local).Path
  if (-not (Test-Path (Join-Path $src 'AndroidGuardian.exe'))) { throw "AndroidGuardian.exe not found in $src" }
  Step "Using files from $src"
} else {
  $tmp = Join-Path $env:TEMP ("AndroidGuardian-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  Step "Looking up the latest release of $Repo"
  $headers = @{ 'User-Agent' = 'AndroidGuardian-installer' }
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
  $asset = $rel.assets | Where-Object { $_.name -like 'AndroidGuardian-win64*.zip' } | Select-Object -First 1
  if (-not $asset) { throw "The latest release ($($rel.tag_name)) has no Windows package. Open https://github.com/$Repo/releases" }
  $zip = Join-Path $tmp 'AndroidGuardian.zip'
  Step "Downloading $($asset.name) ($([math]::Round($asset.size / 1MB, 1)) MB)"
  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $headers
  Step "Unpacking"
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $src = Get-ChildItem $tmp -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'AndroidGuardian.exe') } | Select-Object -First 1 -ExpandProperty FullName
  if (-not $src) { throw 'The package did not contain AndroidGuardian.exe' }
}

# 2. Copy. Keep the user's data/ (settings, threat list) and reports/ from a previous install.
New-Item -ItemType Directory -Path $Dest -Force | Out-Null
Get-ChildItem -Path $src -Force | Where-Object { $_.Name -notin @('data', 'reports') } | ForEach-Object {
  Copy-Item -Path $_.FullName -Destination $Dest -Recurse -Force
}
$srcData = Join-Path $src 'data'
if (Test-Path $srcData) {
  New-Item -ItemType Directory -Path (Join-Path $Dest 'data') -Force | Out-Null
  Get-ChildItem $srcData -File | Where-Object { $_.Name -ne 'config.json' } | Copy-Item -Destination (Join-Path $Dest 'data') -Force
}
Step "Files copied"

# 3. Remove the internet "Mark of the Web" so SmartScreen does not block the exe.
Get-ChildItem -Path $Dest -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
Step "Files unblocked (no SmartScreen prompt)"

$exe = Join-Path $Dest 'AndroidGuardian.exe'
$version = if (Test-Path (Join-Path $Dest 'VERSION')) { (Get-Content (Join-Path $Dest 'VERSION') -Raw).Trim() } else { '0.0.0' }

# 4. Shortcuts (Desktop + Start Menu).
if (-not $NoShortcuts) {
  $ws = New-Object -ComObject WScript.Shell
  $targets = @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"),
    (Join-Path ([Environment]::GetFolderPath('Programs')) "$AppName.lnk")
  )
  foreach ($lnkPath in $targets) {
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = $exe
    $lnk.WorkingDirectory = $Dest
    $lnk.IconLocation = "$exe,0"
    $lnk.Description = 'Find and remove spyware on an Android phone'
    $lnk.Save()
  }
  Step "Shortcuts created on the Desktop and in the Start Menu"
}

# 5. Register in Settings > Apps so there is an Uninstall button.
$sizeKB = [int]((Get-ChildItem $Dest -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
New-Item -Path $RegKey -Force | Out-Null
$props = @{
  DisplayName          = $AppName
  DisplayVersion       = $version
  Publisher            = 'Abdulraham Amer'
  InstallLocation      = $Dest
  DisplayIcon          = $exe
  UninstallString      = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`""
  QuietUninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`" -Quiet"
  URLInfoAbout         = "https://github.com/$Repo"
  HelpLink             = "https://github.com/$Repo#readme"
  InstallDate          = (Get-Date -Format 'yyyyMMdd')
  EstimatedSize        = $sizeKB
  NoModify             = 1
  NoRepair             = 1
}
foreach ($k in $props.Keys) { Set-ItemProperty -Path $RegKey -Name $k -Value $props[$k] }
Step "Registered in Settings > Apps > Installed apps"

if ($tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "Installed $AppName $version." -ForegroundColor Green
Write-Host "  Open it from the Desktop shortcut or the Start Menu."
Write-Host "  To remove it later: Settings > Apps > Installed apps > $AppName > Uninstall."
Write-Host ""
if (-not $NoLaunch) { Start-Process -FilePath $exe -WorkingDirectory $Dest }
