<#
.SYNOPSIS
  Installs Android Guardian for the current Windows user. No administrator rights needed.

.DESCRIPTION
  One line, from PowerShell (Windows PowerShell 5.1 or PowerShell 7):
      irm https://raw.githubusercontent.com/AbdulrahmanAmer/android-guardian/main/installer/install.ps1 | iex
  With options (the one-liner cannot take any):
      & ([scriptblock]::Create((irm https://raw.githubusercontent.com/AbdulrahmanAmer/android-guardian/main/installer/install.ps1))) -Portable D:\AndroidGuardian
  From an unzipped release folder: double-click Install.cmd.

  What it does, exactly:
    1. Downloads the latest release zip from GitHub (or uses -Local <folder or zip>).
       Checks its SHA-256 against SHA256SUMS.txt from the same release and refuses a mismatch.
    2. Closes a running copy, then copies the files to  %LOCALAPPDATA%\Programs\AndroidGuardian.
       On upgrade, your settings (data\config.json), the threat list and reports\ are kept.
    3. Checks every copied file against the package's own SHA256SUMS.txt (catches antivirus removal).
    4. Removes the "downloaded from the internet" mark, so Windows SmartScreen does not warn.
    5. Creates shortcuts on the Desktop and in the Start Menu.
    6. Registers "Android Guardian" in Settings > Apps > Installed apps, with a working Uninstall button.
  Nothing is written anywhere else. uninstall.ps1 reverses every step.

.PARAMETER Local
  Install from an unzipped release folder, or from a release zip file, instead of downloading.
.PARAMETER Portable
  Only unpack into this folder (no shortcuts, no registry entry). Run AndroidGuardian.exe from there.
.PARAMETER Uninstall
  Remove Android Guardian (runs the installed uninstall.ps1). Add -Quiet to skip the question.
.PARAMETER NoShortcuts
  Do not create the Desktop and Start Menu shortcuts.
.PARAMETER NoLaunch
  Do not open Android Guardian when done.

.NOTES
  Exit codes (also left in $LASTEXITCODE when run through iex):
    0  done
    1  unexpected error (the message says what)
    2  bad arguments, or the package folder is incomplete
    3  download failed: no internet, GitHub unreachable, or no release published yet
    4  the download failed its SHA-256 check (nothing was installed)
    5  files could not be replaced or removed (in use, or access denied)
    6  files vanished or changed right after copying (almost always antivirus quarantine)
    7  unsupported system (needs 64-bit Windows 10 or 11)

  This file is ASCII only on purpose: Windows PowerShell 5.1 reads a .ps1 without a BOM as ANSI.
  It never calls 'exit' when run through 'irm | iex', because that would close the user's window.
#>
[CmdletBinding()]
param(
  [string]$Local,
  [string]$Portable,
  [switch]$Uninstall,
  [switch]$Quiet,
  [switch]$NoShortcuts,
  [switch]$NoLaunch,
  [string]$Repo = 'AbdulrahmanAmer/android-guardian'
)

function Invoke-AndroidGuardianSetup {
  [CmdletBinding()]
  param(
    [string]$Local, [string]$Portable, [switch]$Uninstall, [switch]$Quiet,
    [switch]$NoShortcuts, [switch]$NoLaunch, [string]$Repo = 'AbdulrahmanAmer/android-guardian'
  )
  # Function scope: under 'irm | iex' these would otherwise leak into the user's session.
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest in 5.1 is 10x slower with the progress bar

  $AppName = 'Android Guardian'
  $ExeName = 'AndroidGuardian.exe'
  $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\AndroidGuardian'
  $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AndroidGuardian'
  $WinPS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $UA = @{ 'User-Agent' = 'AndroidGuardian-installer' }
  $tmp = $null

  function Say([string]$t) { Write-Host "  $t" }
  function Ok([string]$t) { Write-Host '  [ok] ' -ForegroundColor Green -NoNewline; Write-Host $t }
  function Warn([string]$t) { Write-Host '  [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
  function Fail([int]$code, [string]$msg) {
    $e = New-Object System.Exception $msg
    $e.Data['AGExit'] = $code
    throw $e
  }
  function Box([string]$color, [string[]]$lines) {
    $w = ($lines | Measure-Object -Property Length -Maximum).Maximum + 4
    $bar = '  +' + ('-' * $w) + '+'
    Write-Host ''
    Write-Host $bar -ForegroundColor $color
    foreach ($l in $lines) { Write-Host ('  |  ' + $l.PadRight($w - 2) + '|') -ForegroundColor $color }
    Write-Host $bar -ForegroundColor $color
    Write-Host ''
  }
  function Get-StatusCode($err) {
    try { if ($err.Exception.Response) { return [int]$err.Exception.Response.StatusCode } } catch { }
    return 0
  }
  function Get-Url([string]$url, [string]$outFile) {
    # Three tries, -UseBasicParsing so it works on machines where Internet Explorer was never opened.
    for ($i = 1; $i -le 3; $i++) {
      try { Invoke-WebRequest -Uri $url -OutFile $outFile -Headers $UA -UseBasicParsing; return }
      catch {
        $code = Get-StatusCode $_
        if ($code -eq 404) { throw }
        if ($i -eq 3) { throw }
        Start-Sleep -Seconds (2 * $i)
      }
    }
  }
  function Read-Sums([string]$file) {
    $map = @{}
    foreach ($line in (Get-Content -LiteralPath $file)) {
      if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') { $map[$Matches[2]] = $Matches[1].ToLower() }
    }
    return $map
  }
  function Get-Sha256([string]$file) {
    # .NET directly, not Get-FileHash: 5.1 started from a PowerShell 7 window (via cmd) inherits 7's
    # PSModulePath and then cannot load Get-FileHash. Measured, not theoretical.
    $s = [IO.File]::OpenRead($file)
    try { $h = [Security.Cryptography.SHA256]::Create(); ([BitConverter]::ToString($h.ComputeHash($s)) -replace '-', '').ToLower() }
    finally { $s.Dispose() }
  }
  function Test-Under([string]$path, [string]$dir) {
    $p = $path.TrimEnd('\') + '\'; $d = $dir.TrimEnd('\') + '\'
    return $p.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)
  }
  function Test-Package([string]$dir, [switch]$SkipData) {
    # Checks every file listed in the package's own SHA256SUMS.txt. Returns missing and changed files.
    $r = @{ missing = @(); changed = @(); checked = $false }
    if (-not (Test-Path -LiteralPath (Join-Path $dir $ExeName))) { $r.missing += $ExeName }
    $list = Join-Path $dir 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $list)) { return $r }
    $r.checked = $true
    $sums = Read-Sums $list
    foreach ($name in $sums.Keys) {
      if ($SkipData -and $name.StartsWith('data/')) { continue }   # the app refreshes its threat list itself
      $p =Join-Path $dir ($name.Replace('/', '\'))
      if (-not (Test-Path -LiteralPath $p)) { if ($r.missing -notcontains $name) { $r.missing += $name } }
      elseif ((Get-Sha256 $p) -ne $sums[$name]) { $r.changed += $name }
    }
    return $r
  }
  function Fail-Antivirus([string[]]$names) {
    Fail 6 ("These files are missing or were changed: $($names -join ', ').`n" +
      "  This is almost always antivirus. Open Windows Security > Virus & threat protection > Protection history.`n" +
      "  If it lists Android Guardian: choose Actions > Restore (or Allow), then run setup again.`n" +
      "  The program is open source (https://github.com/$Repo); new unsigned programs that use adb are sometimes flagged.")
  }
  function Stop-Ours([string]$dir) {
    # The app, and the adb server it started: adb.exe from our folder keeps platform-tools\ locked.
    $procs = @(Get-Process -Name AndroidGuardian, adb, aapt2 -ErrorAction SilentlyContinue | Where-Object {
      $p = $null; try { $p = $_.Path } catch { }
      ($p -and (Test-Under $p $dir)) -or (-not $p -and $_.ProcessName -eq 'AndroidGuardian')
    })
    if ($procs.Count) {
      $procs | Stop-Process -Force -ErrorAction SilentlyContinue
      $procs | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
      Ok "Closed the running copy of $AppName"
    }
  }
  function Expand-Zip([string]$zip, [string]$into) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $into) }
    catch { Fail 2 "The zip could not be unpacked ($($_.Exception.Message)). Download it again." }
    $found = Get-ChildItem -LiteralPath $into -Recurse -Filter $ExeName -File | Select-Object -First 1
    if (-not $found) { Fail 2 "The package does not contain $ExeName. Download it again from https://github.com/$Repo/releases/latest" }
    return $found.DirectoryName
  }

  try {
    Write-Host ''
    Write-Host "  $AppName setup" -ForegroundColor Cyan
    Write-Host "  PowerShell $($PSVersionTable.PSVersion) on Windows $([Environment]::OSVersion.Version)" -ForegroundColor DarkGray
    Write-Host ''

    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Fail 7 "$AppName runs on Windows only." }
    if (-not [Environment]::Is64BitOperatingSystem) { Fail 7 "$AppName needs 64-bit Windows 10 or 11." }
    if ($Uninstall -and ($Local -or $Portable)) { Fail 2 '-Uninstall cannot be combined with -Local or -Portable.' }

    # ---------------------------------------------------------------- uninstall (delegates)
    if ($Uninstall) {
      $u = Join-Path $InstallDir 'uninstall.ps1'
      if (Test-Path -LiteralPath $u) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $u)
        if ($Quiet) { $a += '-Quiet' }
        & $WinPS @a | Out-Host
        return [int]$LASTEXITCODE
      }
      # Folder already gone: clean up whatever is left so Settings does not show a dead entry.
      foreach ($lnk in @(
          (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"),
          (Join-Path ([Environment]::GetFolderPath('Programs')) "$AppName.lnk"))) {
        if ((Split-Path $lnk) -and (Test-Path -LiteralPath $lnk)) { Remove-Item -LiteralPath $lnk -Force; Ok "Removed $lnk" }
      }
      if (Test-Path $RegKey) { Remove-Item $RegKey -Recurse -Force; Ok 'Removed the Installed apps entry' }
      Say "$AppName is not installed for this user. Nothing else to remove."
      return 0
    }

    # ---------------------------------------------------------------- where to
    if ($Portable) {
      $Dest = [IO.Path]::GetFullPath($Portable).TrimEnd('\')
      # Never mix into a folder that has other things in it: use a subfolder instead.
      if ((Test-Path -LiteralPath $Dest) -and -not (Test-Path -LiteralPath (Join-Path $Dest $ExeName)) -and
          @(Get-ChildItem -LiteralPath $Dest -Force).Count -gt 0) {
        $Dest = Join-Path $Dest 'AndroidGuardian'
      }
      Say "Unpacking a portable copy into $Dest"
    } else {
      $Dest = $InstallDir
      $prev = (Get-ItemProperty -Path $RegKey -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
      if ($prev -and (Test-Path -LiteralPath (Join-Path $Dest $ExeName))) { Say "Found version $prev already installed: upgrading it in place." }
      Say "Installing into $Dest"
    }
    if ($Dest.Length -gt 200) { Fail 2 "The folder path is too long ($($Dest.Length) characters). Choose a shorter one." }

    # If this PowerShell is sitting inside the folder we are about to change, step out of it.
    if (Test-Under ((Get-Location).ProviderPath) $Dest) { Set-Location -LiteralPath $env:USERPROFILE; Warn "Moved out of $Dest so it can be updated." }
    if (Test-Under ([Environment]::CurrentDirectory) $Dest) { [Environment]::CurrentDirectory = $env:USERPROFILE }

    # ---------------------------------------------------------------- 1. get the files
    $tmp = Join-Path $env:TEMP ('AG-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    if ($Local) {
      if (-not (Test-Path -LiteralPath $Local)) { Fail 2 "Not found: $Local" }
      $item = Get-Item -LiteralPath $Local
      if ($item.PSIsContainer) {
        $src = $item.FullName.TrimEnd('\')
      } else {
        Say "Unpacking $($item.Name)"
        $src = Expand-Zip $item.FullName (Join-Path $tmp 'x')
      }
      Ok "Using the package in $src"
    } else {
      $zip = Join-Path $tmp 'package.zip'
      $sums = Join-Path $tmp 'SHA256SUMS.txt'
      $zipName = $null; $zipUrl = $null; $sumsUrl = $null; $sizeMB = $null; $tag = $null
      Say "Looking up the latest release of $Repo"
      try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $UA -TimeoutSec 30
        $tag = $rel.tag_name
        $asset = $rel.assets | Where-Object { $_.name -like 'AndroidGuardian-win64*.zip' } | Select-Object -First 1
        if ($asset) { $zipName = $asset.name; $zipUrl = $asset.browser_download_url; $sizeMB = [math]::Round($asset.size / 1MB, 1) }
        $s = $rel.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
        if ($s) { $sumsUrl = $s.browser_download_url }
      } catch {
        $code = Get-StatusCode $_
        if ($code -eq 404) { Fail 3 "No release of $AppName has been published yet. See https://github.com/$Repo/releases" }
        # 403/429 = API rate limit (60 requests per hour per address). The plain download links have no limit.
        Warn "GitHub's API did not answer ($(if ($code) { "HTTP $code" } else { $_.Exception.Message })). Using the direct download link."
      }
      if (-not $zipUrl) {
        $sumsUrl = "https://github.com/$Repo/releases/latest/download/SHA256SUMS.txt"
        try { Get-Url $sumsUrl $sums } catch {
          if ((Get-StatusCode $_) -eq 0) {
            Fail 3 "Could not reach GitHub. Check that this PC is online, then run the command again. Or download the zip in a browser from https://github.com/$Repo/releases/latest and double-click Install.cmd inside it."
          }
          Fail 3 "Could not find the latest release ($($_.Exception.Message)). See https://github.com/$Repo/releases/latest"
        }
        $zipName = (Read-Sums $sums).Keys | Where-Object { $_ -like 'AndroidGuardian-win64*.zip' } | Select-Object -First 1
        if (-not $zipName) { Fail 3 "The latest release has no Windows package. See https://github.com/$Repo/releases/latest" }
        $zipUrl = "https://github.com/$Repo/releases/latest/download/$zipName"
      }
      Say ("Downloading $zipName" + $(if ($sizeMB) { " ($sizeMB MB)" } else { '' }) + '. This can take a minute.')
      try { Get-Url $zipUrl $zip } catch {
        Fail 3 "The download failed ($($_.Exception.Message)). Check the internet connection and try again."
      }
      # SHA-256 check against SHA256SUMS.txt from the same release.
      if ($sumsUrl -and -not (Test-Path -LiteralPath $sums)) {
        try { Get-Url $sumsUrl $sums } catch { Warn "Could not download SHA256SUMS.txt ($($_.Exception.Message))." }
      }
      $actual = Get-Sha256 $zip
      if (Test-Path -LiteralPath $sums) {
        $expected = (Read-Sums $sums)[$zipName]
        if (-not $expected) { Fail 4 "SHA256SUMS.txt in the release does not list $zipName. Refusing to install an unverified file." }
        if ($expected -ne $actual) {
          Fail 4 "The download is not the file that was published (SHA-256 $actual, expected $expected). Nothing was installed. Try again later; if it keeps happening, report it at https://github.com/$Repo/issues"
        }
        Ok "Download verified (SHA-256 $($actual.Substring(0, 16))...)"
      } else {
        Warn "This release has no SHA256SUMS.txt, so the download could not be verified. SHA-256: $actual"
      }
      $src = Expand-Zip $zip (Join-Path $tmp 'x')
    }
    $src = [IO.Path]::GetFullPath($src).TrimEnd('\')
    $repair = $src -eq $Dest
    # Check the package itself before touching anything. (In repair mode the folder is the live
    # install, whose data\ the app rewrites, so data\ is skipped there.)
    $pre = Test-Package $src -SkipData:$repair
    if ($pre.missing.Count) { Fail-Antivirus $pre.missing }
    if ($pre.changed.Count) {
      Fail 4 "The package is damaged or was modified: $($pre.changed -join ', ') do not match its SHA256SUMS.txt. Nothing was installed. Download it again from https://github.com/$Repo/releases/latest"
    }
    if ($pre.checked) { Ok 'Package contents verified against its SHA256SUMS.txt' } else { Warn 'The package has no SHA256SUMS.txt, so its files could not be verified.' }
    $newVersion = if (Test-Path -LiteralPath (Join-Path $src 'VERSION')) { (Get-Content -LiteralPath (Join-Path $src 'VERSION') -Raw).Trim() } else { '0.0.0' }

    # ---------------------------------------------------------------- 2. copy
    if (-not $repair -and ((Test-Under $Dest $src) -or (Test-Under $src $Dest))) {
      Fail 2 "The package folder ($src) and the destination ($Dest) overlap. Unzip the package somewhere else first."
    }
    Stop-Ours $Dest
    if ($repair) {
      Ok 'Running from the installed folder: repairing shortcuts and the Installed apps entry only'
    } else {
      New-Item -ItemType Directory -Path $Dest -Force | Out-Null
      try {
        # Replace each program file or folder that is in the new package. data\ and reports\ are merged, never replaced.
        foreach ($it in Get-ChildItem -LiteralPath $src -Force) {
          if ($it.Name -in @('data', 'reports')) { continue }
          $target = Join-Path $Dest $it.Name
          if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
          Copy-Item -LiteralPath $it.FullName -Destination $target -Recurse -Force
        }
        $srcData = Join-Path $src 'data'
        $dstData = Join-Path $Dest 'data'
        New-Item -ItemType Directory -Path $dstData -Force | Out-Null
        if (Test-Path -LiteralPath $srcData) {
          foreach ($f in Get-ChildItem -LiteralPath $srcData -File) {
            if ($f.Name -eq 'config.json') { continue }   # the user's settings, never overwritten
            $t = Join-Path $dstData $f.Name
            # Keep a threat list the app refreshed itself if it is newer than the packaged one.
            if ((Test-Path -LiteralPath $t) -and (Get-Item -LiteralPath $t).LastWriteTimeUtc -gt $f.LastWriteTimeUtc) { continue }
            Copy-Item -LiteralPath $f.FullName -Destination $t -Force
          }
        }
        New-Item -ItemType Directory -Path (Join-Path $Dest 'reports') -Force | Out-Null
      } catch {
        Fail 5 "Could not replace files in $Dest ($($_.Exception.Message)). Close Android Guardian and any window open in that folder, then run setup again."
      }
      Ok "Files copied ($newVersion)"
    }

    # ---------------------------------------------------------------- 3. verify what landed (antivirus check)
    $exe = Join-Path $Dest $ExeName
    Start-Sleep -Seconds 2   # real-time scanners act a moment after a file is written
    $post = Test-Package $Dest -SkipData   # data\ may legitimately hold a newer threat list than the package
    if ($post.missing.Count -or $post.changed.Count) { Fail-Antivirus ($post.missing + $post.changed) }
    Ok 'All files present and intact after copying'

    # ---------------------------------------------------------------- 4. unblock
    Get-ChildItem -LiteralPath $Dest -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Ok 'Removed the "downloaded from the internet" mark (no SmartScreen prompt)'

    if ($Portable) {
      Box Green @("$AppName $newVersion is ready (portable).", '', "Folder:  $Dest", "Start:   double-click $ExeName in that folder", 'Remove:  delete the folder. Nothing else was written.')
      if (-not $NoLaunch) { Start-Process -FilePath $exe -WorkingDirectory $Dest }
      return 0
    }

    # ---------------------------------------------------------------- 5. shortcuts
    $made = @()
    if (-not $NoShortcuts) {
      $ws = New-Object -ComObject WScript.Shell
      # GetFolderPath follows a Desktop redirected to OneDrive; it returns '' if the folder does not exist.
      foreach ($folder in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
        if (-not $folder) { Warn 'A shortcut folder does not exist on this PC; skipped.'; continue }
        $lnkPath = Join-Path $folder "$AppName.lnk"
        $lnk = $ws.CreateShortcut($lnkPath)
        $lnk.TargetPath = $exe
        $lnk.WorkingDirectory = $Dest
        $lnk.IconLocation = "$exe,0"
        $lnk.Description = 'Find and remove spyware on an Android phone'
        $lnk.Save()
        $made += $lnkPath
      }
      Ok 'Shortcuts created on the Desktop and in the Start Menu'
    }

    # ---------------------------------------------------------------- 6. Installed apps entry
    $sizeKB = [int]((Get-ChildItem -LiteralPath $Dest -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
    New-Item -Path $RegKey -Force | Out-Null
    $strings = [ordered]@{
      DisplayName          = $AppName
      DisplayVersion       = $newVersion
      Publisher            = 'Abdulraham Amer'
      InstallLocation      = $Dest
      DisplayIcon          = "$exe,0"
      UninstallString      = "`"$WinPS`" -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`""
      QuietUninstallString = "`"$WinPS`" -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`" -Quiet"
      URLInfoAbout         = "https://github.com/$Repo"
      HelpLink             = "https://github.com/$Repo#readme"
      InstallDate          = (Get-Date -Format 'yyyyMMdd')
    }
    foreach ($k in $strings.Keys) { New-ItemProperty -Path $RegKey -Name $k -Value $strings[$k] -PropertyType String -Force | Out-Null }
    foreach ($k in @{ EstimatedSize = $sizeKB; NoModify = 1; NoRepair = 1 }.GetEnumerator()) {
      New-ItemProperty -Path $RegKey -Name $k.Key -Value $k.Value -PropertyType DWord -Force | Out-Null
    }
    Ok 'Registered in Settings > Apps > Installed apps'

    Box Green @(
      "$AppName $newVersion is installed.", '',
      "Folder:   $Dest",
      $(if ($made.Count) { 'Open it:  Desktop or Start Menu > Android Guardian' } else { "Open it:  $exe" }),
      "Remove:   Settings > Apps > Installed apps > $AppName > Uninstall")
    if (-not $NoLaunch) { Start-Process -FilePath $exe -WorkingDirectory $Dest; Say 'Opening it now. Keep the black window open while you use it.' ; Write-Host '' }
    return 0
  } catch {
    $code = $_.Exception.Data['AGExit']
    if ($null -eq $code) { $code = 1 }
    Write-Host ''
    Write-Host '  Setup did not finish.' -ForegroundColor Red
    foreach ($l in ($_.Exception.Message -split "`n")) { Write-Host "  $($l.Trim())" -ForegroundColor Red }
    if ($code -eq 1) { Write-Host "  ($($_.InvocationInfo.PositionMessage -replace '\s+', ' '))" -ForegroundColor DarkGray }
    Write-Host "  Help: https://github.com/$Repo#faq   (exit code $code)" -ForegroundColor DarkGray
    Write-Host ''
    return [int]$code
  } finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

# Older Windows PowerShell may not offer TLS 1.2 by default; GitHub requires it. Add it, keep the rest.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

$agExit = Invoke-AndroidGuardianSetup @PSBoundParameters
if ($MyInvocation.MyCommand.Path) { exit $agExit }   # run as a file: real exit code
$global:LASTEXITCODE = $agExit                        # run through iex: never 'exit', it would close the window
