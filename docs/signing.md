# Code signing: status, policy and the SignPath Foundation application

**Status (2026-10-31): Windows releases are not code-signed yet.** The project is applying to the
[SignPath Foundation](https://signpath.org), which signs open-source software for free.
Everything below is prepared so the owner only has to submit the form and paste two secrets.

## Why signing matters here

- Windows SmartScreen warns about unsigned programs downloaded with a browser ("Windows protected your PC").
- Some antivirus products are quicker to quarantine new unsigned programs, especially ones that use `adb`.
- Signing does not remove the SmartScreen warning on day one. Reputation builds up per certificate as people
  download and run signed releases. A SignPath Foundation certificate is shared by many projects, so it starts with
  some reputation.

What is already in place without signing:

- The one-line installer downloads with PowerShell (no "downloaded from the internet" mark) and runs
  `Unblock-File`, so installed copies never show the SmartScreen prompt.
- Every release has `SHA256SUMS.txt`; the installer refuses a zip that does not match it, and checks every file
  inside against the package's own `SHA256SUMS.txt`.
- Releases are built only by `.github/workflows/release.yml` on GitHub-hosted runners, from the tagged commit, with
  every action pinned to a commit SHA, and the zip is reproducible (same inputs, same bytes).
- The exe carries version information (product name, version, publisher, description) via Bun's `--windows-*` flags.

## Code signing policy (published text)

SignPath Foundation requires a page titled **"Code signing policy"** on the project's home page, linked from the
download page. The README links here. Once the application is approved, replace the status line at the top of this
file with the block below (wording required by SignPath, kept verbatim):

> Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)
>
> **Team roles**
> - Committers and reviewers: [repository members](https://github.com/AbdulrahmanAmer/android-guardian/graphs/contributors)
> - Approvers: [owner](https://github.com/AbdulrahmanAmer)
>
> **Privacy policy:** see [Privacy](https://github.com/AbdulrahmanAmer/android-guardian#privacy) in the README.
> This program does not transfer information about you or your phone to other networked systems. It downloads a
> public threat list from GitHub once a week, and sends app fingerprints to VirusTotal only if you enter a
> VirusTotal key.

Notes for the owner:

- SignPath offers a stock privacy sentence ("This program will not transfer any information to other networked
  systems unless specifically requested by the user or the person installing or operating it"). Do **not** use it:
  the weekly threat-list download happens without being requested each time. Linking the README's Privacy section,
  as above, is the accurate option, and SignPath allows a link to your own privacy policy.
- The certificate is issued to **SignPath Foundation**, not to you. Windows will show "SignPath Foundation" as the
  publisher. That is normal for this programme; say so in the README when signing starts.
- Everyone with a role (just you, for now) must use **multi-factor authentication** on GitHub and on SignPath.

## Eligibility check (from signpath.org/terms)

| Requirement | Android Guardian |
|---|---|
| OSI-approved licence, no commercial dual licensing, for all components | MIT. Bundled: adb/aapt2 (Apache-2.0), Bun (MIT + LGPL-2 JavaScriptCore). Threat data is CC BY-SA 4.0 data, not code |
| No proprietary code | None |
| No malware or potentially unwanted programs | It removes apps only when the user clicks, and says what it will do first |
| Actively maintained | Yes |
| Already released in the form to be signed | **Needs v0.1.0 published** on GitHub Releases before applying |
| Functionality described on the download page | README "What it finds" |
| Builds on a CI system | GitHub Actions (`release.yml`) |

## Step by step

### 1. Before applying (about 10 minutes)

1. Publish v0.1.0: push the tag `v0.1.0` (see CONTRIBUTING.md, "Release"). Check the release has the zip and
   `SHA256SUMS.txt`.
2. Turn on multi-factor authentication on your GitHub account (Settings → Password and authentication) if it is not on.
3. Check the README has the "Code signing policy" link (it does) and the Privacy section (it does).

### 2. Apply

Open https://signpath.org/apply. The form asks the following (as of 2026-10-31). Suggested answers:

| Field | Answer |
|---|---|
| Project Name | Android Guardian |
| Repository URL | https://github.com/AbdulrahmanAmer/android-guardian |
| Homepage URL | https://github.com/AbdulrahmanAmer/android-guardian |
| Download URL | https://github.com/AbdulrahmanAmer/android-guardian/releases (the page must mention that the project uses SignPath Foundation for code signing; the README's "Code signing policy" link covers this, and the release notes can say it too) |
| Privacy Policy URL | https://github.com/AbdulrahmanAmer/android-guardian#privacy |
| Wikipedia URL (optional) | leave empty |
| Tagline | Finds and removes spyware, stalkerware and remote-access apps on an Android phone from a Windows PC. |
| Category | Security (or the closest option offered) |
| Description | Android Guardian is a free, open-source Windows tool that checks an Android phone over USB for stalkerware, spyware and remote-access trojans, using public threat intelligence (Echap stalkerware indicators) and behaviour analysis, and helps non-technical users remove them or take their permissions away. Nothing is installed on the phone and nothing about the user is uploaded. |
| Reputation | Link anything public: stars, forks, issues, mentions, articles, support organisations that point to it. A brand-new project is weak here; it is fine to apply anyway and say it is new and aimed at victims of stalkerware |
| Maintainer Type | Individual |
| Build System | GitHub Actions |
| First Name / Last Name / Email | your own |
| Company Name | leave empty |
| Primary Discovery Channel | your answer |

Tick the data-processing consent and submit. SignPath replies by email; approval can take a few weeks.

### 3. After approval (about 20 minutes)

SignPath creates an organisation for you. In the SignPath web app:

1. Create a **project** with slug `android-guardian`, linked to the GitHub repository.
2. Add a **trusted build system**: GitHub.com (predefined). This enables origin verification.
3. Create an **artifact configuration** with slug `exe`, using the XML in
   [`docs/signpath-artifact-configuration.xml`](signpath-artifact-configuration.xml). It signs `AndroidGuardian.exe`
   only; `adb.exe` and `aapt2.exe` are already signed by Google.
4. Use the release signing policy SignPath Foundation sets up for you (usually slug `release-signing`; each signing needs your manual approval). If the slug differs, change `signing-policy-slug` below.
5. Create a **CI user**, copy its **API token**.
6. In GitHub: repository Settings → Secrets and variables → Actions → New repository secret:
   - `SIGNPATH_API_TOKEN`: the token from step 5.
   - Variable (not secret) `SIGNPATH_ORGANIZATION_ID`: your organisation ID from SignPath.

### 4. Wire it into the release workflow

Add these steps to `.github/workflows/release.yml` after "Build" and before "Installer round trip".
The SignPath action is pinned to the commit of its `v2` tag as of 2026-10-31; re-check it with
`gh api repos/signpath/github-action-submit-signing-request/git/ref/tags/v2` when you add it.

```yaml
      - name: Upload unsigned exe for signing
        id: unsigned
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: unsigned-exe
          path: dist/AndroidGuardian/AndroidGuardian.exe
          if-no-files-found: error
      - name: Sign with SignPath (waits for your approval in SignPath)
        uses: signpath/github-action-submit-signing-request@c92b958760219087e01f8d67a1669ed57afe2627 # v2
        with:
          api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
          organization-id: ${{ vars.SIGNPATH_ORGANIZATION_ID }}
          project-slug: android-guardian
          signing-policy-slug: release-signing
          artifact-configuration-slug: exe
          github-artifact-id: ${{ steps.unsigned.outputs.artifact-id }}
          wait-for-completion: true
          wait-for-completion-timeout-in-seconds: 3600
          output-artifact-directory: signed
      - name: Repackage with the signed exe
        shell: pwsh
        run: |
          Copy-Item signed\AndroidGuardian.exe dist\AndroidGuardian\AndroidGuardian.exe -Force
          $sig = Get-AuthenticodeSignature dist\AndroidGuardian\AndroidGuardian.exe
          if ($sig.Status -ne 'Valid') { throw "signature is $($sig.Status)" }
          node build.mjs --pinned-tools --skip-compile
```

`--skip-compile` keeps the signed exe and rebuilds `SHA256SUMS.txt` and the zip around it. The `release` job
needs `actions: read` permission added next to `contents: write` for the SignPath action to fetch the artifact.

### 5. First signed release

Tag the next version. Approve the signing request in SignPath when it appears. Then, in the README:

- under "SmartScreen", replace "Code signing is being applied for" with "Releases are signed; Windows shows
  SignPath Foundation as the publisher";
- in this file, replace the status line with the policy block above.

## Later: Microsoft reputation without waiting

If SmartScreen still warns on signed releases for a while, submit each new release file at
https://www.microsoft.com/wdsi/filesubmission as "Software developer", "Incorrectly detected as malware/malicious".
The same form is the fix if Microsoft Defender ever quarantines `AndroidGuardian.exe`.
