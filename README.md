# Lost in Weaponization

> **Forge the artifact. Prove the detection.**

`Lost in Weaponization` is a single PowerShell script that generates
**57 Windows execution artifacts** — LNK, SCT, XLL, VSTO, Office macros,
native PE, CPL, installutil, and more — where **every artifact only
launches `calc.exe`**.

No payloads. No persistence. No network. Just the execution primitives
that detection engineers need to prove their rules actually fire.

> *Lost in weaponization? Now you have a map.*

## Why this name?

Because every detection engineer knows the feeling: drowning in file
formats, wondering which one your rule actually catches. This project is
the map. It forges each primitive, one at a time, calc-only, so you can
detonate it in a lab and watch your detection — or your miss — happen.

## What you get

57 files. 13 categories. One script. All calc-only.

| Category | Formats |
|---|---|
| shell | LNK, URL, settingcontent-ms |
| script | PS1, BAT, CMD, VBS, VBE, JS, JSE, WSF, HTA, WSH, SCT, WSC |
| office | DOCM, DOTM, XLSM, XLAM, PPTM, PPAM, SLK |
| office-extras | XLSB, PPSM, POTM |
| bin | SCR, XLL, VSTO |
| compiled | CPL, OCX, AX |
| dotnet | EXE, DLL (InstallUtil, reflection) |
| native | EXE, DLL, CPL |
| persistence | PS1, REG, MOF, INF, JOB, XML |
| dev | CSPROJ, PROPS, TARGETS, Dockerfile, YML, NUPKG |
| container | WSB |
| doc | PDF, MHTML, MHT |
| misc | EML |

## Authorized use only

Every generated artifact **only launches `calc.exe`**. No malware,
no exfiltration, no C2. But these files **do trigger** security alerts,
ASR rules, AV/EDR blocks, and MOTW warnings.

Use **only** in:
- An isolated VM with snapshot (no real network)
- Systems you own or have written permission to test
- Labs not protected by production controls

**Never** run generated artifacts on production, personal, or third-party
systems. Misuse may violate computer-fraud laws in your jurisdiction.

## Quick start

Basic (no admin):

    .\New-LabArtifacts-ExecOnly.ps1 -OutDir C:\lab\lost-in-weaponization

As Administrator — full pipeline including VSTO cert trust:

    .\New-LabArtifacts-ExecOnly.ps1 -OutDir C:\lab\lost-in-weaponization

## Prerequisites

| Requirement | Purpose |
|---|---|
| Windows 10 / 11 | Target OS |
| PowerShell 5.1+ | Run the script |
| Microsoft Office | DOCM, XLSM, PPTM, XLAM |
| VS 2022 + C++ tools | native XLL, DLL, EXE, CPL |
| .NET Framework 4.x | .NET category, VSTO |
| Windows SDK (mage, sn) | VSTO real ClickOnce |
| Administrator | VSTO cert trust, VHD/VHDX |

## Detection guidance

Capture in lab:
- **Sysmon**: 1, 7, 11, 13, 22
- **Security**: 4688 (with command line)
- **PowerShell**: 4104 (ScriptBlock)
- **Defender/EDR**: ASR rule hits, MOTW events

## Known limitations

- `.slk` — Excel 4.0 macros blocked in Excel 2013+
- `.vsto`, `.application`, `.appref-ms` — need cert in TrustedPublisher
- `.pptm`, `.ppsm`, `.potm` — need Trust Center `VBAWarnings=1`
- `.docm`, `.xlsm` — same

## License

MIT — see [LICENSE](LICENSE).

---

*Lost in weaponization? Now you have a map.*