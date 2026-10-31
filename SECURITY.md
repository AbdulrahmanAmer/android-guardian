# Security policy

## Reporting a problem

If you find a way Android Guardian could be abused, miss a threat it claims to catch, or harm a phone, please open a GitHub issue marked **security**, or contact the maintainer (Abdulraham Amer) privately through the GitHub profile if the details would help an attacker. You will get an answer within seven days.

## What this tool does and does not do

- It reads the phone over USB debugging with Google's `adb`. It never installs anything on the phone.
- The only network traffic it makes: downloading the public stalkerware indicator list from GitHub (weekly), and, only if you enter a VirusTotal key, sending SHA-256 hashes of sideloaded app files to VirusTotal. App files themselves never leave your computer.
- Removal uses the same commands a phone owner can run themselves (`pm uninstall --user 0`, `pm disable-user`, `pm revoke`, `dpm remove-active-admin`, `settings put`). It cannot remove a *device owner* app, modify the system partition, or bypass a locked bootloader. If it cannot remove something, it says so.
- It is not a substitute for a factory reset after a confirmed compromise, and it cannot see firmware-level implants on a rooted or modified phone. The report tells you when the phone looks modified.

## For people in danger

If you suspect someone is monitoring your phone, removing the spyware can alert them. Consider talking to a local support organisation first (the Coalition Against Stalkerware lists them at https://stopstalkerware.org). Use the "Save report" button to keep evidence before removing anything.
