# Code signing (SignPath Foundation)

The full plan, the application answers, and the release-workflow steps are in
[docs/signing.md](../docs/signing.md). The artifact configuration to paste into SignPath is
[docs/signpath-artifact-configuration.xml](../docs/signpath-artifact-configuration.xml).

What signing changes for the installer: nothing. `install.ps1` already removes the download mark and checks
SHA-256 sums; a signed `AndroidGuardian.exe` just makes the zip route (Install.cmd, or running the exe straight
from a browser download) show a named publisher instead of the SmartScreen warning, once reputation builds.
The `.ps1` and `.cmd` files are not signed and do not need to be: they are run with `-ExecutionPolicy Bypass`.
