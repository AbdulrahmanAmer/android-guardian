# Android Guardian

**Find and remove spyware, stalkerware and remote-control trojans on an Android phone, from a Windows PC, over a USB cable.**

Free and open source (MIT). No root needed. Nothing is installed on the phone. Nothing is uploaded anywhere.

Made by Abdulraham Amer.

---

## Install (Windows 10 or 11)

You need: a Windows PC, the Android phone, and a USB cable that carries data (the one that came with the phone does).

### Easiest: one line

1. Press the **Windows key**, type `powershell`, press **Enter**.
2. Paste this line and press **Enter**:

   ```powershell
   irm https://raw.githubusercontent.com/AbdulrahmanAmer/android-guardian/main/installer/install.ps1 | iex
   ```

3. Wait for "Installed Android Guardian". It opens by itself, and you get a shortcut on the Desktop and in the Start Menu.

No administrator password is asked for. It installs only for your Windows user, in `%LOCALAPPDATA%\Programs\AndroidGuardian`.

### Or: download and double-click

1. Download `AndroidGuardian-win64-v….zip` from the [latest release](https://github.com/AbdulrahmanAmer/android-guardian/releases/latest).
2. Right-click the zip, **Extract All…**, open the extracted `AndroidGuardian` folder.
3. Double-click **Install.cmd**. Same result as the one-liner.

   If Windows shows "Windows protected your PC", click **More info**, then **Run anyway**. This appears for any new program that is not yet known to Microsoft; the one-line install above never shows it.

### Or: no install at all (portable)

Extract the zip anywhere, such as a USB stick, and double-click **AndroidGuardian.exe**. Reports and settings stay in that folder.

---

## Use

1. Open **Android Guardian**. A black window appears (keep it open) and your browser opens the guide.
2. **Connect the phone.** The page tells you exactly what to tap. In short:
   - Settings → **About phone** → tap **Build number** seven times (Samsung: About phone → **Software information** → Build number).
   - Settings → **Developer options** (Samsung: at the bottom of Settings; Pixel: System → Developer options) → turn on **USB debugging**.
   - Plug in the cable. On the phone tap **Allow** when it asks "Allow USB debugging?" (tick "Always allow from this computer").
   - Xiaomi / Redmi / POCO: also turn on **USB debugging (Security settings)** in Developer options.
   The page re-checks every few seconds; press **Check again** if you are impatient.
3. Click **Scan this phone**. One to three minutes. Keep the phone unlocked.
4. Read the verdict. Every flagged app lists the exact reasons. For each one choose:
   - **Remove from phone**: uninstalls it (system apps are disabled and wiped instead). Its device-admin and accessibility rights are revoked first so it cannot resist.
   - **Keep, but take its rights away**: leaves it installed but revokes microphone, camera, SMS, call-log, location and contact access, stops it running in the background, cuts its background internet, and removes any special access.
5. **Protect this phone** (optional): switches the phone's Private DNS to Quad9 or AdGuard, which refuse to resolve known spyware and malware servers. Works on Android 9 and newer. Undo any time with **Turn off** or in the phone's Settings → Network → Private DNS.
6. **Save report** keeps an HTML file with everything that was found (also stored in the `reports` folder next to the app).
7. When finished, turn **USB debugging off** again on the phone (Developer options). Close the black window to quit.

### If you think someone is spying on you

Removing spyware can alert the person who installed it. If you are in danger, consider contacting a local support organisation first ([list at stopstalkerware.org](https://stopstalkerware.org)). Save the report before removing anything; it is evidence.

---

## Uninstall

Any one of these:

- **Settings → Apps → Installed apps** (Windows 10: Apps & features) → **Android Guardian** → **Uninstall**.
- Double-click **Uninstall.cmd** in the program folder (`%LOCALAPPDATA%\Programs\AndroidGuardian`).
- PowerShell:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\AndroidGuardian\uninstall.ps1"
  ```

It asks whether to keep your saved reports (they are moved to a folder on your Desktop), then removes the program folder, both shortcuts and the Installed-apps entry. Nothing else was ever written. Portable use: just delete the folder.

Nothing is installed on the phone, so there is nothing to uninstall there. Turn USB debugging off if you no longer need it.

---

## What it checks

**Known threats**

- Package names, APK SHA-256 hashes and signing-certificate SHA-1 fingerprints from the [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) list (the same data Amnesty's Mobile Verification Toolkit uses). Refreshed weekly, or on demand.
- Default package names of common RAT builders (AhMyth, L3MON, DroidJack, AndroRAT, SpyNote, Metasploit payloads, and others).
- Optional: VirusTotal verdicts for sideloaded app files (free API key; only hashes are sent).

**Behaviour** (catches renamed and home-made spyware that is on no list)

- Accessibility service enabled, device administrator, notification access, usage access, battery-optimisation exemption.
- Microphone, camera, SMS, call log, location, contacts and file access, overlay ("draw over other apps") and install rights, and combinations of them.
- No launcher icon, hidden flag, not installed from a store, names imitating system components, debug builds, recently installed, running without an icon.
- Legitimate remote-control apps (TeamViewer, AnyDesk, AirDroid and others) are pointed out so you can confirm you installed them yourself.

**Phone state**

- Device owner or work profile (a fully managed phone), root, unlocked bootloader, verified-boot state, test-keys firmware, security-patch age, Play Protect verification off, developer options on, third-party keyboard or SMS app, Private DNS pointing at a known bad domain.

Scores: **70+ critical**, **40–69 suspicious**, **20–39 watch**. Normal apps from the Play Store stay under 20.

---

## Command line

The exe also works without the interface:

```
AndroidGuardian.exe status
AndroidGuardian.exe scan [--json] [--record DIR] [--replay DIR] [--offline]
AndroidGuardian.exe remove <package>
AndroidGuardian.exe block <package>
AndroidGuardian.exe protect-dns [quad9|adguard|cloudflare|off]
```

`scan` exits 3 if anything critical was found, 1 for suspicious, 0 for clean.

---

## Limits (please read)

- It cannot see firmware-level implants or anything hidden by root on a modified phone. It tells you when the phone looks modified (unlocked bootloader, test keys, root binary); a factory reset is the safe answer then.
- An app installed as **device owner** cannot be removed over USB. Only a factory reset clears it.
- Xiaomi phones refuse setting changes over USB until "USB debugging (Security settings)" is on; removal still works without it.
- Windows SmartScreen warns about any new unsigned program the first time it is run from a download. The one-line installer avoids this. The project is applying for free open-source code signing; until then, the source is here for anyone to read and build.

---

## Build from source, contribute

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: `node test/run.mjs`, `npm run demo`, `node build.mjs`. No npm dependencies. Third-party components and their licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Security notes: [SECURITY.md](SECURITY.md).

## Licence

MIT © 2026 Abdulraham Amer. Known-threat data © Echap, CC BY-SA 4.0.
