## What this changes

<!-- One or two sentences in plain words. -->

## How I checked it

- [ ] `node test/run.mjs` passes (paste the last line)
- [ ] If it touches the interface: rendered light, dark and 390 px wide (`npm run demo`, or `bench shot`), and looked at them
- [ ] If it touches detection rules: the clean-phone fixture still has zero CRITICAL and zero SUSPICIOUS, and a new test covers the rule
- [ ] If it touches removal or the installer: tested on a real phone or a real Windows user account, and I say below what is UNPROVEN

## Rules of this repository

- No npm dependencies. The whole supply chain should fit in one `ls`.
- One writer per file per change; say which files you touched.
- Plain language in anything a user reads. No jargon, no scores without words.
- GitHub Actions stay pinned to commit SHAs.

## What is not proven

<!-- Be honest here; it is the most useful part of the description. -->
