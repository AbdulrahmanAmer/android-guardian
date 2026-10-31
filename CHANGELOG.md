# Changelog

All notable changes to Android Guardian. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-31

First public release.

### Scan

- Reads an Android phone over USB with `adb`. No root. Nothing is installed on the phone.
- Collects installed apps, permissions, accessibility services, device admins, notification listeners,
  usage access, battery exemptions, launcher visibility, installer source, running processes, network totals
  and device state.
- Matches known threats from the Echap stalkerware-indicators list (package names, APK SHA-256,
  signing-certificate SHA-1), refreshed weekly, plus a built-in list of remote-access-trojan builder defaults.
- Scores behaviour with plain-language reasons: critical (70+), suspicious (40-69), watch (20-39).
- Reads APK signing certificates in pure JavaScript (v1 JAR and v2/v3 signing block).
- Optional VirusTotal lookup of sideloaded app hashes with a free API key.

### Act

- **Remove from phone**: revokes device-admin and accessibility rights, then uninstalls (system apps are
  disabled and cleared instead).
- **Keep, but take its rights away**: revokes sensitive permissions and special access, stops background running
  and background data.
- **Protect this phone**: Private DNS to Quad9, AdGuard or Cloudflare; one click to undo.
- HTML report saved in `reports/`.

### Interface

- Local guided web page on `127.0.0.1` with phone detection, step-by-step USB debugging help, and a Quit button.
- Command line: `status`, `scan`, `remove`, `block`, `protect-dns`, `--help`, `--version`, with documented exit codes.

### Windows package and installer

- Single `AndroidGuardian.exe` (Bun runtime included), with `adb` and `aapt2` bundled.
- One-line per-user installer (`irm … | iex`), no administrator rights, works in Windows PowerShell 5.1 and
  PowerShell 7. Verifies the download against the release's `SHA256SUMS.txt` and every file against the package's
  own list; detects antivirus removal; upgrades in place keeping settings and reports; falls back to direct
  download links when the GitHub API is rate-limited.
- Desktop and Start Menu shortcuts, an Installed apps entry with Uninstall and quiet uninstall.
- Uninstaller keeps saved reports on the Desktop unless told otherwise; `-Quiet` for scripted use.
- `Install.cmd` and `Uninstall.cmd` in the zip; `-Portable` to unpack without installing.
- Reproducible zip: pinned, checksum-verified Google tools in CI, sorted entries, fixed timestamps.

[Unreleased]: https://github.com/AbdulrahmanAmer/android-guardian/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AbdulrahmanAmer/android-guardian/releases/tag/v0.1.0
