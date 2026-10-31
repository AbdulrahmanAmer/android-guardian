# Third-party components

Android Guardian itself is MIT licensed (see `LICENSE`), © 2026 Abdulraham Amer.
The source tree has **no npm dependencies**. The Windows release package also contains the components below.

| Component | What it does here | Where in the package | Licence |
|---|---|---|---|
| Android SDK Platform-Tools: `adb.exe`, `AdbWinApi.dll`, `AdbWinUsbApi.dll`, `libwinpthread-1.dll` | Talks to the phone over USB | `platform-tools/` | Apache License 2.0 (Android Open Source Project). Notices: `platform-tools/NOTICE.txt` |
| Android SDK Build-Tools: `aapt2.exe` | Reads an app's display name from its APK file | `tools/` | Apache License 2.0 (Android Open Source Project). Notices: `tools/NOTICE.txt` |
| Bun runtime | The JavaScript runtime compiled into `AndroidGuardian.exe` | inside the exe | MIT. Bun statically links JavaScriptCore/WebKit (LGPL-2) and other libraries under their own licences, listed below |
| Echap stalkerware-indicators | Public list of known stalkerware package names, hashes, certificates and domains | `data/stalkerware.stix2` (refreshed weekly from GitHub) | CC BY-SA 4.0 |

## Android SDK Platform-Tools and Build-Tools

Copyright © The Android Open Source Project. Licensed under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). The binaries are redistributed unmodified, exactly as published
by Google at https://dl.google.com/android/repository/ (or copied from an Android SDK installed by the same
means). The `NOTICE.txt` file shipped next to each set of binaries contains the full notices of every
component they include, and is part of this package as the Apache License requires.

The package's own `THIRD_PARTY_NOTICES.md` ends with a table of the exact versions it contains.

## Bun

Bun is MIT licensed: https://github.com/oven-sh/bun/blob/main/LICENSE.md

Bun statically links JavaScriptCore and WebKit, which are licensed under the GNU Lesser General Public License
version 2 (LGPL-2). As that licence requires, the source of the WebKit version Bun uses is available at
https://github.com/oven-sh/WebKit, and Bun's licence file explains how to rebuild Bun with a modified copy.
`AndroidGuardian.exe` is produced with `bun build --compile` from the unmodified Bun release named in the
package's version table, and the complete source of Android Guardian is in this repository, so the program can be
rebuilt against a modified Bun.

Other libraries Bun links (each under its own licence, listed in Bun's licence file): BoringSSL, brotli, c-ares,
libbase64, ICU, libuv (Windows), lol-html, ls-hpack, ls-qpack, lsquic, mimalloc, picohttpparser, simdutf,
tinycc (LGPL-2.1), uSockets, zlib-ng, zstd.

## Echap stalkerware-indicators

© Echap and contributors. https://github.com/AssoEchap/stalkerware-indicators

Licensed under Creative Commons Attribution-ShareAlike 4.0 International
(https://creativecommons.org/licenses/by-sa/4.0/). Android Guardian uses the file `generated/stalkerware.stix2`
unmodified; it reads it to match apps on the phone. The same data is used by Amnesty International's Mobile
Verification Toolkit.

## Other

The app icon (`assets/icon.ico`) is drawn by `installer/make-icon.ps1` in this repository (MIT).
No other third-party code, fonts or images are bundled.
