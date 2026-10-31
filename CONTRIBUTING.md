# Contributing

Thank you for helping people find spyware on their phones.

## Run from source

```
git clone https://github.com/AbdulrahmanAmer/android-guardian
cd android-guardian
node test/run.mjs          # tests against a recorded infected phone (no device needed)
npm run demo               # the interface, driven by the recording
npm start                  # the interface, with a real phone on USB
```

Needs Node 20 or newer. There are no npm dependencies on purpose; please keep it that way (the whole supply chain of this tool should fit in one `ls`).

## Add a detection rule

Rules live in `lib/rules.mjs`. Each rule adds points and a plain-language reason. Add a test in `test/run.mjs`; if the rule needs new phone output, extend `test/make-fixture.mjs` (it generates `test/fixtures/infected/commands.json`, a fake phone with known-bad and known-good apps).

Score bands: 70+ critical, 40–69 suspicious, 20–39 watch. A rule that would push a normal Play Store app over 20 on its own is too aggressive.

## Record a real phone for a bug report

```
node guardian.mjs scan --record my-phone
```

writes `my-phone/commands.json`. It contains package names, permissions and settings, **not** your messages or files, but read through it before attaching it to an issue.

## Build the Windows package

```
node build.mjs
```

Needs Bun (https://bun.sh) and either the Android SDK on your machine or an internet connection (the script downloads Google's platform-tools and build-tools zips). Output: `dist/AndroidGuardian-win64-v<version>.zip` and `dist/SHA256SUMS.txt`.

## Release

Bump `version` in `package.json`, commit, tag `vX.Y.Z`, push the tag. The Release workflow builds on a clean Windows runner and attaches the zip to a GitHub release. The install one-liner always fetches the latest release.
