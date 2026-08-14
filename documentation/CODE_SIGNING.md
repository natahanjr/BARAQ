# BARAQ — Binary Code Signing

**Document:** Signing the shipped binaries so SmartScreen and antivirus
engines stop flagging them
**Status:** tooling ready; requires purchasing an Authenticode certificate

---

## 1. Why code signing is mandatory for selling

- **SmartScreen**: unsigned installers trigger "Windows protected your PC"
  warnings on customer machines.
- **Antivirus**: unsigned fresh binaries (especially PyInstaller bundles)
  frequently produce false positives.
- **Trust**: a signed, reputation-bearing certificate is the standard
  trust signal for commercial Windows software.
- **Integrity**: signatures let customers verify the file was not tampered
  with between your build and their machine.

## 2. What you need to buy

| Item | Purpose | Typical cost |
|---|---|---|
| Code-signing certificate (EV preferred) | Authenticode signatures; EV earns immediate SmartScreen reputation | ~$200–500/year |
| Hardware token (EV usually requires a USB token or cloud HSM) | Protects the private key | included/small fee |
| Windows SDK signtool | The signing tool itself (free) | free |

Alternatives: Azure Trusted Signing (cloud, no USB token, ~$10/month) or
SignPath (CI-based). Any of them produce valid Authenticode signatures.

## 3. Installing signtool (Windows SDK)

```powershell
winget install Microsoft.WindowsSDK.10.0.26100 --accept-source-agreements
# signtool lands under:
#   C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe
```

## 4. Signing script

`scripts/sign_binaries.ps1` signs the installer, the server exe and the
agent exe. Usage:

```powershell
# From the repository root (installs the cert into the store first if asked)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign_binaries.ps1 `
  -CertPfx C:\secure\code-signing.pfx `
  -CertPassword "pfx password" `
  -TimestampUrl "http://timestamp.digicert.com"

# Or sign from an already-installed certificate in the store:
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign_binaries.ps1 `
  -StoreSubject "BARAQ Signing Co"
```

The script signs (and embeds a timestamp so signatures survive cert
expiry), then verifies each file with `signtool verify /pa`.

## 5. Integrating with the release build

`scripts/build_release.ps1` automatically signs every artifact when a
certificate is available. Set one of:

```powershell
$env:BARAQ_SIGN_CERT_PFX    = "C:\secure\code-signing.pfx"
$env:BARAQ_SIGN_CERT_PASS   = "pfx password"
$env:BARAQ_SIGN_TIMESTAMP   = "http://timestamp.digicert.com"
```

…and run the normal build. If neither the env vars nor an installed
certificate are present, the build proceeds unsigned and prints a warning.

## 6. Verification checklist

- [ ] `signtool verify /pa /v` passes on the installer and both exes
- [ ] Digital signature tab visible in Windows Explorer properties
- [ ] SmartScreen shows the publisher name (reputation builds after the
      first downloads; EV certificates get an immediate green screen)
- [ ] Private key never leaves the hardware token / HSM
- [ ] Re-sign after any rebuild (signatures are invalidated by rebuilds)