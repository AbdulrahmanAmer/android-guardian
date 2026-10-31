# Changelog

All notable changes to Android Guardian. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-31

The interface, redesigned.

### Interface
- A soft colour field behind one frosted glass panel; light and dark follow the system.
- A step rail (Connect, Scan, Results, Protect) with rings that show real progress and the active step lifted out; the connection chip hangs from the panel's top edge.
- Each app is a card with a score ring (0 to 100 in the severity colour), one plain sentence saying what it does, and the full reasons one click away.
- One family of pill buttons; the DNS provider is a segmented choice instead of a dropdown; the confirmation dialog matches.
- Scanning shows the steps as a list with the current step ringed; the raw log is folded away.
- Idle rings no longer show a stray dot; narrow screens get a plain chip and no rail.
- The design system lives in `design/` (tokens, components, demos, renders, traced reference outline) and is inlined into the single-file bundle at build time.

### Command line
- `status` exits 2 when no phone is ready, the same code `scan` uses.

### Build
- The exe resolves its own path through symlinks, so a portable install started via a link still finds the bundled adb.

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
