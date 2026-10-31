# Third-party components

Android Guardian itself is MIT licensed (see LICENSE). The release package also contains:

| Component | What it is | Where it is in the package | Licence |
|---|---|---|---|
| Android Debug Bridge (`adb.exe`, `AdbWinApi.dll`, `AdbWinUsbApi.dll`, `libwinpthread-1.dll`) | Google's tool for talking to an Android phone over USB | `platform-tools/` | Apache License 2.0 (Android Open Source Project). Full notices in `platform-tools/NOTICE.txt`. |
| `aapt2.exe` | Android Asset Packaging Tool, used only to read an app's display name out of its APK | `tools/` | Apache License 2.0 (Android Open Source Project) |
| Bun runtime | The JavaScript runtime compiled into `AndroidGuardian.exe` | inside the exe | MIT (Bun), with components under their own licences (JavaScriptCore: LGPL 2.1 / BSD; see https://bun.sh/docs/project/licensing) |
| Echap stalkerware-indicators | Public list of known stalkerware package names, hashes, certificates and domains | `data/stalkerware.stix2`, refreshed from GitHub | CC BY-SA 4.0 (https://github.com/AssoEchap/stalkerware-indicators) |

No other third-party code is bundled. The source tree has zero npm dependencies.
