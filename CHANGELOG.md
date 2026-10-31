# Changelog

## 0.1.0 (2026-10-31)

First release.

- Scan an Android phone over USB (adb, no root): installed apps, permissions, accessibility services, device admins, notification listeners, usage access, battery exemptions, launcher visibility, installer, running processes, network totals, device state.
- Known-threat matching: Echap stalkerware-indicators (package names, APK SHA-256, signing-certificate SHA-1), refreshed weekly; built-in list of RAT builder defaults.
- Behaviour scoring with plain-language reasons; critical / suspicious / watch bands.
- Pure-JavaScript APK signing-certificate reader (v1 JAR signatures and v2/v3 signing block).
- Optional VirusTotal hash lookup with a free API key.
- Remove (uninstall, or disable + clear for system apps), Keep-but-disarm (revoke permissions, strip special access, block background and background data), Protect (Private DNS to Quad9 / AdGuard / Cloudflare), device-setting fixes.
- Guided local web interface with phone detection and step-by-step USB debugging instructions; HTML report.
- Standalone Windows package: single exe (Bun), bundled adb and aapt2, one-line installer with Desktop and Start Menu shortcuts, Installed-apps entry and uninstaller.
