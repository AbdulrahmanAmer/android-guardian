# Progress and position

Position file for anyone (or any session) picking this project up. Newest block first.

## 2026-10-31 · v0.2.0 · interface redesigned on glass

**Done and verified**
- Live interface uses the "Cutout on glass" design system in `design/` (tokens, components.css/js), inlined into the single-file bundle by `build.mjs --ui-only`. States rendered and checked with the bench: Connect, Scanning, Results (light, dark, 390 px). Screenshots in `docs/screenshots/`.
- App cards: score ring 0–100 in the severity colour, one plain sentence (`says()` in `ui/index.html`), reasons folded under "Why". One pill button family; segmented DNS choice; dialog matches; scanning as a step list.
- `status` exits 2 without a phone; CI smoke step ends with an explicit `exit 0` (pwsh quirk: last native non-zero exit fails the step).
- Tests: `node test/run.mjs` → 30 passed plus 11 / 31 / 25 / 25 / 24 in the five suites. CI green on ubuntu-24.04 and windows-2025 (tests, package build with Google tools hash-checked, installer round trip, exe smoke).
- v0.1.0 one-line installer proven end to end on this PC against the real release (install, shortcuts, registry, quiet uninstall, all gone).

**UNPROVEN**
- No real phone has ever been scanned. All device behaviour rests on three recorded fixtures (`test/fixtures/infected`, `legacy-xiaomi`, `work-pixel`) and a synthetic clean phone.
- Windows 10, antivirus quarantine, non-English Windows, SignPath signing: not exercised.

**Open**
- Companion phone app (phase 2; brief in the session notes: ContentProvider queried over `adb shell content query`, labels/icons, consent screen).
- winget manifest (`installer/winget/`), SignPath application (needs the owner's identity), private vulnerability reporting toggle (owner, repo settings).
- The HTML report (`lib/report.mjs`) still follows the first design, not the glass one.
- Rail hides below 860 px; a phone-width bottom tab bar exists only as a demo (`design/components/bar.html`).

**How to work here**
- `npm run demo` → interface on a recorded phone. `bench shot http://127.0.0.1:<port>/ --full` to look.
- Design from a reference: `bench trace --auto-rotate --overlay`, `bench fit --mirror` (skill `design-bench`, global).
- Release: bump `package.json` and `lib/paths.mjs` VERSION, add CHANGELOG entry, commit, tag `vX.Y.Z`, push tag.
