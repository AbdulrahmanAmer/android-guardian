# Security policy

## Reporting a vulnerability

Please report privately first. Do not put exploit details in a public issue.

1. **Preferred:** on GitHub, open the repository's **Security** tab and click **Report a vulnerability**
   (GitHub private vulnerability reporting). Only the maintainer sees it.
2. **If that button is not there:** open a normal issue titled "Security contact request", with **no details**.
   The maintainer (Abdulraham Amer) will reply with a private channel.

What helps: the version (`AndroidGuardian.exe --version`), what you did, what happened, and what you expected.
If a phone recording is useful (`scan --record <folder>`), say so; do not attach it publicly.

What to expect:

- A first answer within **7 days**.
- A fix or a clear plan within **30 days** for anything that can harm a user or a phone.
- Credit in the release notes, if you want it.
- Please allow up to **90 days**, or until a fixed release is out, before publishing details.

In scope: the program, the installer and uninstaller scripts, the build and release workflows, and the
detection logic (including a way for spyware to hide from it, or a false "clean" result).

## Supported versions

Only the latest release gets fixes. The installer always installs the latest release, and running it again upgrades.

## Verifying a download

Every release has a `SHA256SUMS.txt`. The one-line installer checks the zip against it automatically.
To check by hand in PowerShell:

```powershell
(Get-FileHash .\AndroidGuardian-win64-v0.1.0.zip -Algorithm SHA256).Hash
```

Compare with the line in `SHA256SUMS.txt` from the same release. Inside the zip, `AndroidGuardian/SHA256SUMS.txt`
lists every file; the installer checks those too. Releases are built only by the public GitHub Actions workflow
in `.github/workflows/release.yml`, from the tagged commit, with every action pinned to a commit SHA.

## What this tool does and does not do

- It reads the phone over USB debugging with Google's `adb`. It never installs anything on the phone.
- Its only network traffic: the public Echap indicator list from GitHub (weekly), and, only if you enter a
  VirusTotal key, SHA-256 fingerprints of sideloaded apps to VirusTotal. App files never leave your computer.
- Its local web page listens on `127.0.0.1` only and rejects requests from other origins.
- Removal uses the same commands a phone owner can run (`pm uninstall --user 0`, `pm disable-user`, `pm revoke`,
  `dpm remove-active-admin`, `settings put`). It cannot remove a *device owner* app, change the system partition,
  or bypass a locked bootloader. If it cannot remove something, it says so.
- It is not a substitute for a factory reset after a confirmed compromise, and it cannot see firmware-level
  implants on a rooted or modified phone. The report says when the phone looks modified.

## For people in danger

If you suspect someone is monitoring your phone, removing the spyware can alert them. Consider talking to a
local support organisation first; the Coalition Against Stalkerware lists them at https://stopstalkerware.org.
Save the report before removing anything; it is evidence.
