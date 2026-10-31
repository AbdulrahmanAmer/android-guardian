---
name: Something did not work
about: The program crashed, the phone was not detected, a removal failed, the installer broke
title: ""
labels: bug
---

**What happened**
<!-- In your own words. What did you click, what did you expect, what did you see instead? -->

**Your setup**
- Windows version:
- Android Guardian version (bottom of the page, or `AndroidGuardian.exe --version`):
- Phone maker and model, Android version:
- Installed with the one-line command, the zip, or portable?

**Scan recording (optional, very helpful)**
Run this in the Android Guardian folder with the phone connected, then attach the `commands.json` it writes:
```
AndroidGuardian.exe scan --record my-phone
```
It contains package names, permissions and settings, **not** your messages, photos or files. Read through it before attaching if you prefer. If the issue is about a specific app, say which package name.

**Screenshots or the report**
<!-- "Save report" in the interface produces an HTML file you can attach. Remove anything personal first. -->
