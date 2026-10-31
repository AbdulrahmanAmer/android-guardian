# Contributing

Thank you for helping people find spyware on their phones.

## Ground rules

- **No npm dependencies.** Not for code, not for tests, not for the build. The whole supply chain of this tool
  should fit in one `ls`. Node's standard library, Bun's compiler and Google's `adb`/`aapt2` are all it uses.
- **Plain language.** Every reason the app shows, and every line of the README, is read by frightened,
  non-technical people. Short sentences. No jargon without an explanation.
- **Never harm a phone.** A change that modifies a phone needs a test in `test/` against a recorded phone.
- GitHub Actions in `.github/workflows/` stay pinned to full commit SHAs.

## Run from source

Needs Node 20 or newer. Bun is only needed to build the Windows package.

```
git clone https://github.com/AbdulrahmanAmer/android-guardian
cd android-guardian
node test/run.mjs          # all tests (runs test/*.test.mjs too); no phone needed
npm run demo               # the interface, driven by a recorded infected phone
npm start                  # the interface, with a real phone on USB (adb from your Android SDK or PATH)
node guardian.mjs --help   # the command line
```

`npm start` and `npm run demo` first run `node build.mjs --ui-only`, which writes `lib/ui-bundle.mjs` from
`ui/index.html` (that file is generated and not committed).

## Add a detection rule

Rules live in `lib/rules.mjs`. Each rule adds points and a plain-language reason. Add a test in
`test/rules.test.mjs` (or `test/run.mjs`). If the rule needs new phone output, extend `test/make-fixture.mjs`
(it generates `test/fixtures/infected/commands.json`, a fake phone with known-bad and known-good apps), or add a
recorded fixture under `test/fixtures/`.

Score bands: 70+ critical, 40-69 suspicious, 20-39 watch. A rule that pushes a normal Play Store app over 20 on
its own is too aggressive.

## Report a false positive or a missed app

Use the issue templates. A recording helps most:

```
node guardian.mjs scan --record my-phone          # from source
AndroidGuardian.exe scan --record my-phone         # from the package
```

This writes `my-phone/commands.json`: package names, permissions and settings. It does **not** contain your
messages, photos or files. Read it before you attach it, and remove anything you do not want to share.

## Build the Windows package

```
node build.mjs                    # full build
node build.mjs --pinned-tools     # what CI does: Google's pinned adb/aapt2 zips instead of your local SDK
node build.mjs --skip-compile     # reuse the last exe (docs or installer changes only)
node build.mjs --no-iocs          # do not bundle the Echap threat list
```

Needs Windows, Node 22+ (recommended; 20.15+ works), and [Bun](https://bun.sh). `adb` and `aapt2` come from your
Android SDK (`%LOCALAPPDATA%\Android\Sdk`, or `ANDROID_HOME`) or, if it is missing or `--pinned-tools` is set,
from Google's official zips, downloaded into `.cache/` and checked against the SHA-1 Google publishes.

Output:

- `dist/AndroidGuardian/`: the program folder (exe, `platform-tools/`, `tools/`, installer scripts, `VERSION`,
  `THIRD_PARTY_NOTICES.md` with exact versions, and `SHA256SUMS.txt` for every file).
- `dist/AndroidGuardian-win64-v<version>.zip` and `dist/SHA256SUMS.txt`.

The zip is deterministic: the same inputs give the same bytes (sorted entries, timestamps fixed to the last
commit time). The exe embeds Bun, so use the same Bun version as CI (`bun-version` in the workflows) to compare.

Test the installer against your build without touching the internet:

```
powershell -NoProfile -ExecutionPolicy Bypass -File installer\install.ps1 -Local dist\AndroidGuardian -NoLaunch
powershell -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\AndroidGuardian\uninstall.ps1" -Quiet
```

Installer scripts must stay **ASCII only** (Windows PowerShell 5.1 reads a `.ps1` without a BOM as ANSI) and must
parse in both Windows PowerShell 5.1 and PowerShell 7. CI checks both.

## Release

1. Update `version` in `package.json` and add a section to `CHANGELOG.md`.
2. Commit, then tag and push: `git tag v0.1.1 && git push origin v0.1.1`.
3. The **Release** workflow tests, builds on a clean Windows runner with the pinned tools, runs the installer
   round trip, and publishes the zip and `SHA256SUMS.txt` with generated notes.
   The tag must match `package.json`, or the workflow stops.
4. The one-line installer always fetches the latest release, so users get it on their next install or update.

To try the release build without publishing: Actions → Release → Run workflow, enter the tag, leave
"publish" off. The package is attached to the run as an artifact.

## Pull requests

Keep them small and focused. The PR template has the checklist. By contributing you agree your work is released
under the MIT licence, and to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
